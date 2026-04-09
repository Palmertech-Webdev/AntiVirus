import type { SVGProps } from "react";

export type NavigationIconName =
  | "dashboard"
  | "incidents"
  | "devices"
  | "identities"
  | "email"
  | "alerts"
  | "policies"
  | "reports"
  | "administration";

interface SvgIconProps extends SVGProps<SVGSVGElement> {
  title?: string;
}

interface BrandMarkProps extends SvgIconProps {
  tone?: "accent" | "ok" | "warning" | "danger";
}

function toneColor(tone: NonNullable<BrandMarkProps["tone"]>) {
  switch (tone) {
    case "ok":
      return "var(--ok)";
    case "warning":
      return "var(--warning)";
    case "danger":
      return "var(--danger)";
    default:
      return "var(--accent)";
  }
}

export function BrandMark({ className, tone = "accent", title = "AntiVirus", ...props }: BrandMarkProps) {
  const signal = toneColor(tone);

  return (
    <svg
      viewBox="0 0 48 48"
      fill="none"
      role="img"
      aria-label={title}
      className={className}
      {...props}>
      <rect x="4" y="4" width="40" height="40" rx="14" fill="rgba(108, 194, 255, 0.1)" stroke="rgba(108, 194, 255, 0.22)" />
      <path
        d="M24 10.5L33.6 14.7V22.5C33.6 29.6 28.8 35.8 24 38.4C19.2 35.8 14.4 29.6 14.4 22.5V14.7L24 10.5Z"
        fill="rgba(237, 244, 251, 0.98)"
      />
      <path
        d="M17.8 24.4H21L23.2 19.5L25.3 28.4L27.1 23.5H30.4"
        stroke={signal}
        strokeWidth="2.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx="30.8" cy="16.8" r="2.3" fill={signal} />
    </svg>
  );
}

export function NavGlyph({ name, className, title, ...props }: SvgIconProps & { name: NavigationIconName }) {
  const common = {
    stroke: "currentColor",
    strokeWidth: 1.8,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const
  };

  return (
    <svg viewBox="0 0 20 20" fill="none" role="img" aria-label={title ?? name} className={className} {...props}>
      {name === "dashboard" ? (
        <>
          <rect x="2.5" y="3" width="6" height="5.5" rx="1.2" {...common} />
          <rect x="11.5" y="3" width="6" height="8.5" rx="1.2" {...common} />
          <rect x="2.5" y="11.5" width="6" height="5.5" rx="1.2" {...common} />
          <rect x="11.5" y="14.5" width="6" height="2.5" rx="1.2" {...common} />
        </>
      ) : null}
      {name === "incidents" ? (
        <>
          <path d="M10 2.6L15.8 5.2V9.9C15.8 14 12.9 17.5 10 19C7.1 17.5 4.2 14 4.2 9.9V5.2L10 2.6Z" {...common} />
          <path d="M10 6.4V11" {...common} />
          <circle cx="10" cy="14.1" r="0.8" fill="currentColor" />
        </>
      ) : null}
      {name === "devices" ? (
        <>
          <rect x="2.7" y="3.4" width="14.6" height="10.1" rx="1.8" {...common} />
          <path d="M7.2 16.6H12.8" {...common} />
          <path d="M10 13.5V16.6" {...common} />
        </>
      ) : null}
      {name === "identities" ? (
        <>
          <circle cx="10" cy="6.2" r="3.1" {...common} />
          <path d="M4.3 16.8C5.5 13.9 7.4 12.6 10 12.6C12.6 12.6 14.5 13.9 15.7 16.8" {...common} />
        </>
      ) : null}
      {name === "email" ? (
        <>
          <rect x="2.6" y="4.1" width="14.8" height="11.8" rx="1.6" {...common} />
          <path d="M3.8 5.3L10 10.1L16.2 5.3" {...common} />
        </>
      ) : null}
      {name === "alerts" ? (
        <>
          <path d="M10 3.1C12.7 3.1 14.5 5 14.5 7.7V10.2C14.5 11.4 15 12.5 15.8 13.4L16.7 14.4H3.3L4.2 13.4C5 12.5 5.5 11.4 5.5 10.2V7.7C5.5 5 7.3 3.1 10 3.1Z" {...common} />
          <path d="M8.1 16.2C8.5 17.1 9.1 17.5 10 17.5C10.9 17.5 11.5 17.1 11.9 16.2" {...common} />
        </>
      ) : null}
      {name === "policies" ? (
        <>
          <path d="M4 5.4H16" {...common} />
          <path d="M4 10H16" {...common} />
          <path d="M4 14.6H16" {...common} />
          <circle cx="7" cy="5.4" r="1.7" fill="var(--bg)" stroke="currentColor" strokeWidth="1.8" />
          <circle cx="12.8" cy="10" r="1.7" fill="var(--bg)" stroke="currentColor" strokeWidth="1.8" />
          <circle cx="9.1" cy="14.6" r="1.7" fill="var(--bg)" stroke="currentColor" strokeWidth="1.8" />
        </>
      ) : null}
      {name === "reports" ? (
        <>
          <path d="M3 16.5H17" {...common} />
          <rect x="4.2" y="9.9" width="2.5" height="6.6" rx="1" {...common} />
          <rect x="8.7" y="6.8" width="2.5" height="9.7" rx="1" {...common} />
          <rect x="13.2" y="4.3" width="2.5" height="12.2" rx="1" {...common} />
        </>
      ) : null}
      {name === "administration" ? (
        <>
          <circle cx="10" cy="10" r="2.3" {...common} />
          <path d="M10 3.1V4.5" {...common} />
          <path d="M10 15.5V16.9" {...common} />
          <path d="M16.9 10H15.5" {...common} />
          <path d="M4.5 10H3.1" {...common} />
          <path d="M14.9 5.1L13.9 6.1" {...common} />
          <path d="M6.1 13.9L5.1 14.9" {...common} />
          <path d="M14.9 14.9L13.9 13.9" {...common} />
          <path d="M6.1 6.1L5.1 5.1" {...common} />
        </>
      ) : null}
    </svg>
  );
}
