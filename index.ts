import { serve } from '@hono/node-server';
import { Hono, Context } from 'hono';
import { StatusCode } from 'hono/utils/http-status';
import { cors } from 'hono/cors';
import https from 'https';
// Import isAxiosError for type checking
import axios, { AxiosInstance, AxiosResponse, isAxiosError } from 'axios';
import isValidUrl from 'is-valid-http-url';
import ipaddr from 'ipaddr.js';
import { Buffer } from 'buffer';

// --- Configuration Constants ---
const PORT = 8181;
const ALLOWED_ORIGIN_SUFFIX = '.solanatracker.io';
const PRIMARY_IPFS_GATEWAY = 'ipfs-forward.solanatracker.io';
const FALLBACK_IPFS_GATEWAY = 'sapphire-working-koi-276.mypinata.cloud';
const MAX_RETRIES = 3;
const REQUEST_TIMEOUT = 5000;
const RETRY_DELAY = 1000;
const USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.1';

const ALLOWED_IMAGE_TYPES: Set<string> = new Set([
  'image/jpeg',
  'image/png',
  'image/gif',
  'image/webp',
  'image/bmp',
  'image/tiff',
]);

// WARNING: rejectUnauthorized: false disables SSL/TLS certificate validation.
// This is insecure and should ONLY be used if you absolutely trust the target servers
// or in a controlled environment. Consider alternative solutions like trusting specific CAs.
const httpsAgent = new https.Agent({
  rejectUnauthorized: false, // SECURITY RISK!
  keepAlive: true,
});

const axiosInstance: AxiosInstance = axios.create({
  httpsAgent,
  timeout: REQUEST_TIMEOUT,
  maxRedirects: 1, // Axios default is 5, explicitly setting to 1 as per original code intent
  headers: {
    'User-Agent': USER_AGENT,
  },
  responseType: 'arraybuffer', // Expecting binary data
});

const app = new Hono();

// --- Middleware ---
app.use(
  '*',
  cors({
    // Add explicit type for origin parameter
    origin: (origin: string): string | undefined => {
      // Check if origin is defined and ends with the allowed suffix
      if (origin && origin.endsWith(ALLOWED_ORIGIN_SUFFIX)) {
        return origin;
      }
      // Return undefined to deny other origins, especially important with credentials: true
      return undefined;
    },
    allowMethods: ['POST', 'GET', 'OPTIONS'],
    credentials: true,
  })
);

// --- Helper Functions ---

/**
 * Validates if a URL is allowed based on protocol, hostname, and IP address range.
 * Prevents requests to localhost, private networks, and metadata services.
 * @param urlString - The URL string to validate.
 * @returns True if the URL is allowed, false otherwise.
 */
function isAllowedUrl(urlString: string): boolean {
  try {
    if (!isValidUrl(urlString)) {
      console.warn(`URL validation failed (is-valid-http-url): ${urlString}`);
      return false;
    }

    const parsedUrl = new URL(urlString);

    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      console.warn(`URL validation failed (protocol): ${parsedUrl.protocol}`);
      return false;
    }

    const hostname = parsedUrl.hostname;

    // Use a Set for efficient lookup
    const disallowedHostnames: Set<string> = new Set([
      'localhost',
      '127.0.0.1',
      '::1', // IPv6 loopback
      '169.254.169.254', // AWS metadata service IP
    ]);

    if (disallowedHostnames.has(hostname)) {
      console.warn(`URL validation failed (disallowed hostname): ${hostname}`);
      return false;
    }

    // Attempt to parse hostname as IP address for range checks
    try {
      const addr = ipaddr.parse(hostname);
      const range = addr.range();

      // Check against various private/reserved ranges
      const isDisallowedRange =
        range === 'loopback' ||
        range === 'private' ||
        range === 'linkLocal' ||
        range === 'uniqueLocal' ||
        range === 'reserved' ||
        hostname.startsWith('10.') || // Explicitly check common private prefixes
        hostname.startsWith('192.168.');

      if (isDisallowedRange) {
        console.warn(
          `URL validation failed (IP address range): ${hostname} (Range: ${range})`
        );
        return false;
      }

      // Specific check for 172.16.0.0/12 range if it's IPv4
      if (ipaddr.IPv4.isIPv4(hostname)) { // Check if it's an IPv4 address first
          const ipV4Addr = ipaddr.IPv4.parse(hostname);
          // Match against the 172.16.0.0/12 CIDR block
          if (ipV4Addr.match(ipaddr.IPv4.parseCIDR('172.16.0.0/12'))) {
               console.warn(
                `URL validation failed (IP address range 172.16/12): ${hostname}`
               );
              return false;
          }
      }
    } catch (e) {
      // Hostname is not a valid IP address, which is fine (it's likely a domain name).
      // No action needed here, proceed with domain validation.
    }

    // If all checks pass
    return true;
  } catch (error) {
    // Catch errors during URL parsing or validation itself
    console.error(`Error during URL validation for ${urlString}:`, error);
    return false;
  }
}

/**
 * Checks if the content type is an allowed image MIME type.
 * Handles potential charset information in the header.
 * @param contentType - The Content-Type header value.
 * @returns True if the content type is allowed, false otherwise.
 */
function isAllowedContentType(contentType: string | undefined | null): boolean {
  if (!contentType) {
    return false;
  }
  // Extract the MIME type part (before any ';') and convert to lowercase
  const mimeType = contentType.toLowerCase().split(';')[0].trim();
  return ALLOWED_IMAGE_TYPES.has(mimeType);
}

// --- Routes ---

app.get('/', (c: Context) => {
  return c.json({ message: 'Solanatracker.io Image Proxy' }, 200);
});

app.get('/proxy', async (c: Context) => {
  const rawUrl = c.req.query('url');

  if (!rawUrl) {
    return c.json({ error: 'Missing url query parameter' }, 400);
  }

  let targetUrl: string;
  try {
    // Decode the URL provided in the query parameter
    targetUrl = decodeURIComponent(rawUrl);
  } catch (e) {
    // Handle potential errors during decoding (e.g., malformed URI)
    return c.json({ error: 'Invalid URL encoding' }, 400);
  }

  // Initial validation of the decoded URL
  if (!isAllowedUrl(targetUrl)) {
     console.log(`Initial URL validation failed for: ${targetUrl}`);
    return c.json({ error: 'URL not allowed' }, 403);
  }


  // Replace known public IPFS gateways with the primary internal gateway
  targetUrl = targetUrl.replace(/cf-ipfs\.com/g, PRIMARY_IPFS_GATEWAY);
  targetUrl = targetUrl.replace(/ipfs\.io/g, PRIMARY_IPFS_GATEWAY);

  // Re-validate the URL after potential transformations (base64 decoding, gateway replacement)
  if (!isAllowedUrl(targetUrl)) {
    console.log(`Transformed URL validation failed for: ${targetUrl}`);
    return c.json({ error: 'Transformed URL not allowed' }, 403);
  }

  let lastError: Error | null = null;

  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    let currentUrl = targetUrl;

    // On the final attempt, if using the primary IPFS gateway, switch to the fallback
    if (attempt === MAX_RETRIES - 1 && currentUrl.includes(PRIMARY_IPFS_GATEWAY)) {
      currentUrl = currentUrl.replace(PRIMARY_IPFS_GATEWAY, FALLBACK_IPFS_GATEWAY);
      // Validate the newly generated fallback URL
        if (!isAllowedUrl(currentUrl)) {
            console.warn(`Fallback IPFS gateway URL rejected: ${currentUrl}`);
            // Indicate server-side issue generating/validating the fallback
            return c.json({ error: 'Fallback URL generation failed validation' }, 500);
        }
    }

    try {
      console.log(`Attempt ${attempt + 1}/${MAX_RETRIES}: Fetching ${currentUrl}`);
      // Make the request, expecting an ArrayBuffer (Buffer in Node.js)
      // Explicitly type the response
      const response: AxiosResponse<Buffer> = await axiosInstance.get<Buffer>(currentUrl);

      // Extract content-type header safely
      const contentTypeHeader = response.headers['content-type'];
      let contentType: string | undefined;
      if (Array.isArray(contentTypeHeader)) {
         // Though unlikely for Content-Type, handle array possibility
          contentType = contentTypeHeader[0];
      } else {
          contentType = contentTypeHeader;
      }


      // Validate the content type of the response
      if (!isAllowedContentType(contentType)) {
        console.warn(`Content type not allowed: ${contentType} from ${currentUrl}`);
        c.status(403); // Set forbidden status
        return c.json({ error: 'Content type not allowed' });
      }

      // Set security headers on the response
      c.header('X-Content-Type-Options', 'nosniff');
      // CSP for images: allows images from self (the proxy) and data URIs. Disallows other sources.
      c.header('Content-Security-Policy', "default-src 'none'; img-src 'self' data:; style-src 'none'; script-src 'none';");
      // Set the Content-Type based on the fetched image, default if missing
      c.header('Content-Type', contentType || 'application/octet-stream');

      // Return the image data
      return c.body(response.data);

    } catch (error: unknown) { // Catch error as unknown for safer type checking
        // Use axios type guard
        if (isAxiosError(error)) {
            lastError = error; // Store the AxiosError object
            console.error(
                `Attempt ${attempt + 1}/${MAX_RETRIES} failed for ${currentUrl}: ${error.message}`,
                error.code ? `(Code: ${error.code})` : ''
            );

            // If a response was received (even an error response)
            if (error.response) {
                console.error(`Status: ${error.response.status}, Data: ${error.response.data ? error.response.data.toString().substring(0, 100) : 'N/A' }`); // Log response details
                // Stop retrying on 4xx client errors from the upstream server
                if (error.response.status >= 400 && error.response.status < 500) {
                    console.warn(`Received client error ${error.response.status}, stopping retries.`);
                    c.status(error.response.status as StatusCode); // Reflect the upstream status code
                    return c.json({ error: `Failed to retrieve image: Upstream server returned ${error.response.status}` });
                }
            } else if (error.request) {
                // Request was made but no response received (e.g., timeout, network error)
                console.error('No response received for the request.');
            } else {
                // Error happened setting up the request
                console.error('Error setting up the request:', error.message);
            }
        } else if (error instanceof Error) {
           // Handle non-Axios errors (e.g., URL parsing, custom errors)
           lastError = error;
           console.error(
               `Attempt ${attempt + 1}/${MAX_RETRIES} failed for ${currentUrl} (Non-HTTP Error):`,
               error.message
           );
           // Optionally break the loop immediately for non-recoverable errors
           // break;
        } else {
            // Handle cases where the thrown value is not an Error object
            lastError = new Error(`An unknown error occurred: ${String(error)}`);
            console.error(
               `Attempt ${attempt + 1}/${MAX_RETRIES} failed for ${currentUrl} (Unknown Error Type):`,
               error
           );
           // break; // Likely best to stop retries here too
        }


      // If not the last attempt, wait before retrying
      if (attempt < MAX_RETRIES - 1) {
         console.log(`Waiting ${RETRY_DELAY}ms before next retry...`);
        await new Promise((resolve) => setTimeout(resolve, RETRY_DELAY));
      }
    }
  } // End of retry loop

  // If all retries fail
  console.error(`All ${MAX_RETRIES} attempts failed for original URL: ${targetUrl}. Last error:`, lastError?.message);
  c.status(500); // Internal Server Error
  return c.json({ error: 'Failed to retrieve image after multiple attempts' });
});

// --- Server Startup ---
serve({
  fetch: app.fetch,
  port: PORT,
});

console.log(`Server listening on http://localhost:${PORT}`);