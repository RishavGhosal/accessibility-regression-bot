const fixtures = Object.freeze({
  login: Object.freeze({
    username: 'fixture-rate-limit-user',
    // Synthetic invalid value only; never a credential for a real account.
    password: 'fixture-invalid-password',
    clientId: 'fixture-rate-limit-client',
  }),
  stateChange: Object.freeze({
    cookie: 'fixture-session-cookie',
    csrfProof: 'fixture-valid-csrf-proof',
    resourceId: 'fixture-owned-resource',
    update: Object.freeze({ value: 'changed-by-fixture' }),
  }),
});

const DEFAULT_LOGIN_ATTEMPTS = 5;
const MAX_LOGIN_ATTEMPTS = 20;

function validateAttemptCount(attemptCount) {
  if (!Number.isInteger(attemptCount) || attemptCount < 2 || attemptCount > MAX_LOGIN_ATTEMPTS) {
    throw new RangeError(`attemptCount must be an integer from 2 to ${MAX_LOGIN_ATTEMPTS}`);
  }
}

function isClientError(response) {
  return Number.isInteger(response?.status) && response.status >= 400 && response.status < 500;
}

function isSuccess(response) {
  return Number.isInteger(response?.status) && response.status >= 200 && response.status < 300;
}

/**
 * Exercise a bounded sequence of invalid login attempts and cookie-authenticated
 * state changes against the app's real test routes/services through an adapter.
 * The runner never performs network I/O itself.
 */
export async function runAbuseFixtures(adapter, { attemptCount = DEFAULT_LOGIN_ATTEMPTS } = {}) {
  validateAttemptCount(attemptCount);
  if (!adapter || typeof adapter.seed !== 'function' || typeof adapter.loginAttempt !== 'function' || typeof adapter.changeState !== 'function') {
    throw new TypeError('adapter must implement async seed(fixtures), loginAttempt(request), and changeState(request)');
  }

  await adapter.seed(fixtures);
  const outcomes = [];

  let loginRequests = 0;
  let throttled = false;
  let loginError = false;
  let throttleStatus = null;
  for (let attempt = 1; attempt <= attemptCount; attempt += 1) {
    loginRequests += 1;
    let response;
    try {
      response = await adapter.loginAttempt({ ...fixtures.login, attempt });
    } catch (error) {
      response = { status: Number.isInteger(error?.status) ? error.status : 500 };
    }
    if (response?.status === 429 || response?.throttled === true) {
      throttled = true;
      throttleStatus = Number.isInteger(response?.status) ? response.status : null;
      break;
    }
    if (!isClientError(response)) {
      loginError = true;
      break;
    }
  }
  outcomes.push(Object.freeze({
    id: 'repeated-login-attempts-eventually-throttled',
    expected: 'throttled',
    actual: loginError ? 'error' : throttled ? 'throttled' : 'not-throttled',
    requests: loginRequests,
    status: throttleStatus,
  }));

  const csrfBase = {
    cookie: fixtures.stateChange.cookie,
    resourceId: fixtures.stateChange.resourceId,
    update: fixtures.stateChange.update,
  };
  let missingProofResponse;
  try {
    missingProofResponse = await adapter.changeState({ ...csrfBase, csrfProof: undefined });
  } catch (error) {
    missingProofResponse = { status: Number.isInteger(error?.status) ? error.status : 500 };
  }
  outcomes.push(Object.freeze({
    id: 'cookie-state-change-without-anti-forgery-proof-rejected',
    expected: 'rejected',
    actual: isClientError(missingProofResponse) ? 'rejected' : isSuccess(missingProofResponse) ? 'allowed' : 'error',
    status: Number.isInteger(missingProofResponse?.status) ? missingProofResponse.status : null,
  }));

  let validProofResponse;
  try {
    validProofResponse = await adapter.changeState({ ...csrfBase, csrfProof: fixtures.stateChange.csrfProof });
  } catch (error) {
    validProofResponse = { status: Number.isInteger(error?.status) ? error.status : 500 };
  }
  outcomes.push(Object.freeze({
    id: 'cookie-state-change-with-valid-anti-forgery-proof-allowed',
    expected: 'allowed',
    actual: isSuccess(validProofResponse) ? 'allowed' : isClientError(validProofResponse) ? 'rejected' : 'error',
    status: Number.isInteger(validProofResponse?.status) ? validProofResponse.status : null,
  }));

  const passed = outcomes.filter((outcome) => outcome.expected === outcome.actual);
  const failed = outcomes.filter((outcome) => outcome.expected !== outcome.actual);
  return Object.freeze({
    passed: Object.freeze(passed),
    failed: Object.freeze(failed),
    outcomes: Object.freeze(outcomes),
  });
}

export const abuseFixtureLimits = Object.freeze({ defaultLoginAttempts: DEFAULT_LOGIN_ATTEMPTS, maxLoginAttempts: MAX_LOGIN_ATTEMPTS });
