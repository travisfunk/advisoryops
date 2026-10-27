// Redirect www.devicelantern.com/<path> to https://devicelantern.com/<path>.
export default {
  fetch(request) {
    const url = new URL(request.url);
    url.protocol = 'https:';
    url.hostname = 'devicelantern.com';
    return Response.redirect(url.toString(), 301);
  },
};
