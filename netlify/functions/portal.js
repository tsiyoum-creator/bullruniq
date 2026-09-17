// BullrunIQ — "Manage subscription" entry point.
exports.handler = async function () {
  const url = process.env.STRIPE_PORTAL_URL;
  // Only redirect to the official Stripe billing portal domain.
  const safe = url && /^https:\/\/billing\.stripe\.com\//.test(url) ? url : "/contact";
  return {
    statusCode: 302,
    headers: { Location: safe },
    body: "",
  };
};
