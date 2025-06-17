import Bottleneck from "bottleneck";

/**
 * Creates and configures a Bottleneck rate limiter for API requests.
 * Implements a dynamic token refresh mechanism based on a moving average.
 *
 * @param {number} TPM - Tokens per minute.
 * @param {number} RPM - Requests per minute.
 * @param {number} INTERVAL - Interval in milliseconds for refreshing tokens.
 * @param {number} MARGIN - Margin to prevent overuse.
 * @returns {Bottleneck & { getLastReservoir: () => number }} Configured rate limiter instance with a custom method.
 */
export type ReservoirLimiter = Bottleneck & {
  getLastReservoir: () => number;
};

export const createRateLimiter = (
  TPM: number,
  RPM: number,
  INTERVAL = 120,
  MARGIN = 0.9,
): ReservoirLimiter => {
  const limiter = new Bottleneck({
    minTime: Math.floor(60000 / (RPM * MARGIN)),
    reservoir: TPM,
  }) as ReservoirLimiter;

  let tokensConsumed = 0;
  let lastRefreshTime = Date.now();
  let lastReservoir = TPM * MARGIN;

  setInterval(() => {
    const now = Date.now();
    const elapsedTime = now - lastRefreshTime;

    const tokensToAdd = Math.floor((TPM * MARGIN / 60000) * elapsedTime);
    tokensConsumed = Math.max(0, tokensConsumed - tokensToAdd);
    const newReservoir = Math.min(TPM * MARGIN, TPM * MARGIN - tokensConsumed);

    limiter.updateSettings({ reservoir: newReservoir });
    lastReservoir = newReservoir;
    lastRefreshTime = now;
  }, INTERVAL);

  limiter.on("executing", (jobInfo) => {
    const weight = jobInfo.options?.weight || 1;
    tokensConsumed += weight;
  });

  limiter.getLastReservoir = () => lastReservoir;

  return limiter;
};
