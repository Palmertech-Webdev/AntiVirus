import { buildServer } from "./app.ts";

const port = Number(process.env.PORT ?? 4000);
const requestedHost = process.env.HOST?.trim();
const host =
  !requestedHost || requestedHost === "localhost" || requestedHost === "127.0.0.1" || requestedHost === "::1"
    ? "0.0.0.0"
    : requestedHost;

const app = buildServer();

try {
  app.log.info({ host, port }, "Starting control plane listener");
  await app.listen({ port, host });
} catch (error) {
  app.log.error(error);
  process.exit(1);
}
