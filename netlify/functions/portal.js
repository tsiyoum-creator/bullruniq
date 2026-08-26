// BullrunIQ — "Manage subscription" entry point.
exports.handler = async function () {
  const url = process.env.STRIPE_PORTAL_URL;
  return {
    statusCode: 302,
    headers: {
      Location: url || "/contact",
      "Cache-Control": "no-store, no-cache, must-revalidate",
    },
    body: "",
  };
};
