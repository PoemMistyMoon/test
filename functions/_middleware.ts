import { CFP_ALLOWED_PATHS } from './constants';
import { getCookieKeyValue } from './utils';
import { getTemplate } from './template';

export async function onRequest(context: {
  request: Request;
  next: () => Promise<Response>;
  env: { CFP_PASSWORD?: string };
}): Promise<Response> {
  const { request, next, env } = context;
  const { pathname, searchParams } = new URL(request.url);
  const { error, token } = Object.fromEntries(searchParams);
  const cookie = request.headers.get('cookie') || '';
  const cookieKeyValue = await getCookieKeyValue(env.CFP_PASSWORD);

  // Check if the token in the URL matches the CFP_PASSWORD
  if (
    cookie.includes(cookieKeyValue) ||
    (request.method == "POST" && pathname === '/cfp_login') ||
    CFP_ALLOWED_PATHS.includes(pathname) ||
    !env.CFP_PASSWORD ||
    token === env.CFP_PASSWORD // New condition to bypass password protection
  ) {
    // Correct hash in cookie, allowed path, no password set, or correct token in URL
    return await next();
  } else {
    // No cookie or incorrect hash in cookie, or missing/incorrect token. Redirect to login.
    return new Response(getTemplate({ redirectPath: pathname, withError: error === '1' }), {
      headers: {
        'content-type': 'text/html'
      }
    });
  }
}
