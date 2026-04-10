import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

/** @type {import("next").NextConfig} */
const projectRoot = dirname(fileURLToPath(import.meta.url));

const nextConfig = {
  reactStrictMode: true,
  turbopack: {
    root: projectRoot
  }
};

export default nextConfig;
