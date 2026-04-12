import { buildServer } from "./app.ts";
import { USING_DEFAULT_ADMIN_MFA_SECRET, USING_DEFAULT_ADMIN_PASSWORD } from "./adminAuth.ts";

const port = Number(process.env.PORT ?? 4000);
const requestedHost = process.env.HOST?.trim();
const host = requestedHost && requestedHost.length > 0 ? requestedHost : "127.0.0.1";

const app = buildServer();

function isLoopbackHost(value: string) {
  const normalized = value.trim().toLowerCase();
  return normalized === "localhost" || normalized === "127.0.0.1" || normalized === "::1";
}

if (!isLoopbackHost(host) && (USING_DEFAULT_ADMIN_PASSWORD || USING_DEFAULT_ADMIN_MFA_SECRET)) {
  app.log.error(
    {
      host,
      usingDefaultAdminPassword: USING_DEFAULT_ADMIN_PASSWORD,
      usingDefaultAdminMfaSecret: USING_DEFAULT_ADMIN_MFA_SECRET
    },
    "Refusing to bind control-plane externally while bootstrap admin credentials are still default"
  );
  process.exit(1);
}

if (USING_DEFAULT_ADMIN_PASSWORD || USING_DEFAULT_ADMIN_MFA_SECRET) {
  app.log.warn(
    {
      host,
      usingDefaultAdminPassword: USING_DEFAULT_ADMIN_PASSWORD,
      usingDefaultAdminMfaSecret: USING_DEFAULT_ADMIN_MFA_SECRET
    },
    "Control-plane is using default bootstrap admin secrets; set FENRIR_ADMIN_PASSWORD and FENRIR_ADMIN_MFA_SECRET"
  );
}

try {
  app.log.info({ host, port }, "Starting control plane listener");
  await app.listen({ port, host });
} catch (error) {
  app.log.error(error);
  process.exit(1);
}
