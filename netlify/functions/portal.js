// BullrunIQ — "Manage subscription" entry point.
exports.handler = async function () {
  const url = process.env.STRIPE_PORTAL_URL;
  // Only redirect to Stripe's billing domain to prevent open-redirect if env var is misconfigured.
  const safeUrl = url && /^https:\/\/billing\.stripe\.com\//.test(url) ? url : null;
  return {
    statusCode: 302,
    headers: { Location: safeUrl || "/contact" },
    body: "",
  };
};
