package main

import (
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/gascity/gasworks/internal/config"
	"github.com/gascity/gasworks/internal/dpop"
	"github.com/gascity/gasworks/internal/httpc"
	"github.com/gascity/gasworks/internal/sts"
)

// transientAuthError marks a TRANSIENT pre-exchange failure (an id_token refresh that failed on a
// 5xx/429/network/timeout, or a lock/cooldown short-circuit) that a still-valid cached credential
// may cover via serve-last-good — as opposed to a DEFINITIVE session expiry (invalid_grant / a
// 4xx), which genuinely needs an interactive `gasworks login`. Keeping the login remedy for the
// definitive case only stops a headless fleet from being told to "log in" during a Keycloak
// brownout (S2-DESIGN §5.4, FIX 3).
type transientAuthError struct {
	stage string
	err   error
}

func (e *transientAuthError) Error() string {
	return fmt.Sprintf("%s is temporarily unavailable (%s)", e.stage, e.err)
}

func (e *transientAuthError) Unwrap() error { return e.err }

// resilientContext runs discovery with the same bounded transient-retry ladder as the exchange
// (STS 429/5xx and network/timeout): up to maxMintAttempts within the overall deadline, each
// attempt clamped to the remaining budget. A definitive failure (401/403/404/other 4xx) returns
// immediately so the caller can branch to serve-last-good vs a hard error (FIX 3/4).
func resilientContext(cfg config.Config, idToken string, overall time.Time) (sts.ContextResolution, error) {
	deadline := earliest(time.Now().Add(mintLadderBudget), overall)
	var lastErr error
	for attempt := 0; attempt < maxMintAttempts; attempt++ {
		if attempt > 0 {
			delay := backoffDelay(attempt)
			if time.Now().Add(delay).After(deadline) {
				break
			}
			time.Sleep(delay)
		}
		perAttempt, ok := clampStep(deadline, contextTimeout)
		if !ok {
			break
		}
		res, err := sts.Context(cfg, idToken, true, perAttempt)
		if err == nil {
			return res, nil
		}
		if !isTransient(err) {
			return sts.ContextResolution{}, err
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("discovery ladder exhausted")
	}
	return sts.ContextResolution{}, lastErr
}

// Mint-path resilience budgets. bd runs the credential helper under a ~30s exec cap, so every
// network step is bounded and the whole exchange ladder plus serve-last-good must fit inside
// it (S2-DESIGN §5.4).
const (
	// perAttemptTimeout bounds each STS exchange attempt so one hang cannot eat the exec cap.
	perAttemptTimeout = 5 * time.Second
	// contextTimeout / loginTimeout bound the pre-exchange discovery and session steps.
	contextTimeout = 5 * time.Second
	loginTimeout   = 5 * time.Second
	// refreshTimeout bounds the Keycloak refresh held under the store lock (§5.5).
	refreshTimeout = 10 * time.Second
	// mintLadderBudget caps the whole exchange retry ladder so ladder + serve-last-good fit
	// inside the exec cap.
	mintLadderBudget = 15 * time.Second
	// maxMintAttempts is the exchange retry count on transient (5xx/429/network) failures.
	maxMintAttempts = 3
	// backoffBase is the exponential backoff base: retry n waits backoffBase*2^(n-1) + jitter.
	backoffBase = 250 * time.Millisecond
	// eiaJitterSecs spreads the early-refresh skew — a cached EIA is re-minted when it has
	// fewer than eiaSkewSecs + rand(0..eiaJitterSecs) seconds left — so a fleet does not all
	// re-mint on one boundary.
	eiaJitterSecs = 15
	// serveLastGoodFloorSecs is the true-validity floor below which a still-valid cached EIA is
	// NOT served on a mint failure, so bd's ~10s expiry skew cannot instantly re-stale it into
	// a helper-exec storm.
	serveLastGoodFloorSecs = 15
	// minStepFloor is the least remaining budget worth starting a network step with; below it the
	// caller prefers serve-last-good/die over a doomed sub-timeout call — and never hands httpc a
	// non-positive timeout (which it would treat as the 30s default, blowing the exec cap).
	minStepFloor = 300 * time.Millisecond
)

// overallBudget is the single end-to-end deadline for the whole getToken mint chain. bd runs the
// credential helper under a ~30s exec cap, so every network step is clamped to the time remaining
// before this deadline and the per-step timeouts can never SUM past it — leaving headroom for
// serve-last-good instead of a bd SIGKILL (S2-DESIGN §5.4, FIX 4). It is a var so tests can
// shrink it; production keeps ~5s of headroom under the 30s cap.
var overallBudget = 25 * time.Second

// clampStep returns the per-step timeout clamped to the overall deadline. ok is false when the
// remaining budget is below minStepFloor: the caller must NOT start the step and should fall back
// to serve-last-good/die.
func clampStep(deadline time.Time, step time.Duration) (timeout time.Duration, ok bool) {
	rem := time.Until(deadline)
	if rem < minStepFloor {
		return 0, false
	}
	if rem < step {
		return rem, true
	}
	return step, true
}

// earliest returns the earlier of two deadlines.
func earliest(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// resilientExchange runs the EIA exchange with a bounded retry ladder for transient failures
// (STS 429/5xx and network/timeout errors): up to maxMintAttempts within mintLadderBudget,
// exponential backoff + jitter between attempts, each attempt bounded by perAttemptTimeout.
// A non-transient failure (401/403/other 4xx) returns immediately so the caller can branch.
func resilientExchange(cfg config.Config, sessionToken, product, scope string, key *dpop.Key, overall time.Time) (sts.EIA, error) {
	// The ladder gets its own budget, but never runs past the overall deadline (FIX 4).
	deadline := earliest(time.Now().Add(mintLadderBudget), overall)
	var lastErr error
	for attempt := 0; attempt < maxMintAttempts; attempt++ {
		if attempt > 0 {
			delay := backoffDelay(attempt)
			if time.Now().Add(delay).After(deadline) {
				break
			}
			time.Sleep(delay)
		}
		perAttempt, ok := clampStep(deadline, perAttemptTimeout)
		if !ok {
			break
		}
		res, err := sts.Exchange(cfg, sessionToken, product, scope, key, perAttempt)
		if err == nil {
			return res, nil
		}
		if !isTransient(err) {
			return sts.EIA{}, err
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("mint ladder exhausted")
	}
	return sts.EIA{}, lastErr
}

// backoffDelay is backoffBase*2^(attempt-1) plus up to backoffBase of jitter.
func backoffDelay(attempt int) time.Duration {
	base := backoffBase << (attempt - 1) // 250ms, 500ms, ...
	return base + time.Duration(rand.Int63n(int64(backoffBase)))
}

// isTransient reports whether err is worth retrying: a network/timeout error (not an
// *httpc.HTTPError) or an STS 429/5xx. A 403 (denied) and other 4xx are not retried; the 401
// one-shot session re-establishment is handled by the caller.
func isTransient(err error) bool {
	var he *httpc.HTTPError
	if !errors.As(err, &he) {
		return true // network / timeout / connection error
	}
	return he.Status == 429 || he.Status >= 500
}

// eiaReadSkew is the jittered remaining-seconds threshold below which a cached EIA is
// re-minted: eiaSkewSecs + rand(0..eiaJitterSecs).
func eiaReadSkew() int64 {
	return int64(eiaSkewSecs) + rand.Int63n(int64(eiaJitterSecs)+1)
}
