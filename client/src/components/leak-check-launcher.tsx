/**
 * LeakCheckLauncher — opens external breach-check sites pre-filled with a target.
 * Zero backend cost: all checks happen in the analyst's browser on the external site.
 */

import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { ShieldQuestion, ExternalLink, Copy, Globe } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

export type LeakCheckTargetType = "email" | "domain" | "ip" | "auto";

interface Site {
  label: string;
  url: (value: string) => string;
  types: LeakCheckTargetType[];
}

const SITES: Site[] = [
  // Email-specific
  {
    label: "HaveIBeenPwned",
    url: (v) => `https://haveibeenpwned.com/account/${encodeURIComponent(v)}`,
    types: ["email"],
  },
  {
    label: "LeakCheck.io",
    url: (v) => `https://leakcheck.io/?check=${encodeURIComponent(v)}`,
    types: ["email"],
  },
  {
    label: "DeHashed",
    url: (v) => `https://dehashed.com/search?query=${encodeURIComponent(v)}`,
    types: ["email", "domain"],
  },
  {
    label: "BreachDirectory",
    url: (v) => `https://breachdirectory.org/?search=${encodeURIComponent(v)}`,
    types: ["email", "domain"],
  },
  {
    label: "IntelligenceX",
    url: (v) => `https://intelx.io/?s=${encodeURIComponent(v)}`,
    types: ["email", "domain", "ip"],
  },
  {
    label: "Hunter.io Verify",
    url: (v) => `https://hunter.io/email-verifier/${encodeURIComponent(v)}`,
    types: ["email"],
  },
  {
    label: "Snusbase (manual paste)",
    url: () => `https://snusbase.com/`,
    types: ["email"],
  },
  // Domain-specific
  {
    label: "URLScan.io",
    url: (v) => `https://urlscan.io/search/#domain%3A${encodeURIComponent(v)}`,
    types: ["domain"],
  },
  {
    label: "PasteBin DMP",
    url: (v) => `https://psbdmp.ws/api/v3/search/${encodeURIComponent(v)}`,
    types: ["domain", "email"],
  },
  {
    label: "EmailRep.io",
    url: (v) => `https://emailrep.io/${encodeURIComponent(v)}`,
    types: ["domain", "email"],
  },
  // IP-specific
  {
    label: "Shodan",
    url: (v) => `https://www.shodan.io/host/${encodeURIComponent(v)}`,
    types: ["ip"],
  },
  {
    label: "GreyNoise",
    url: (v) => `https://viz.greynoise.io/ip/${encodeURIComponent(v)}`,
    types: ["ip"],
  },
  {
    label: "AbuseIPDB",
    url: (v) => `https://www.abuseipdb.com/check/${encodeURIComponent(v)}`,
    types: ["ip"],
  },
  {
    label: "VirusTotal",
    url: (v) => `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(v)}`,
    types: ["ip", "domain"],
  },
];

function detectType(value: string): LeakCheckTargetType {
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return "email";
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) return "ip";
  return "domain";
}

interface Props {
  value: string;
  type?: LeakCheckTargetType;
  size?: "sm" | "icon";
}

export function LeakCheckLauncher({ value, type = "auto", size = "sm" }: Props) {
  const { toast } = useToast();
  const resolvedType = type === "auto" ? detectType(value) : type;
  const applicableSites = SITES.filter((s) => s.types.includes(resolvedType));

  function openSite(site: Site) {
    const url = site.url(value);
    window.open(url, "_blank", "noopener,noreferrer");
  }

  function copyAllUrls() {
    const urls = applicableSites
      .map((s) => `${s.label}: ${s.url(value)}`)
      .join("\n");
    navigator.clipboard.writeText(urls).then(() => {
      toast({ title: "Copied", description: `${applicableSites.length} breach-check URLs copied to clipboard` });
    });
  }

  return (
    <TooltipProvider>
      <DropdownMenu>
        <Tooltip>
          <TooltipTrigger asChild>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size={size} data-testid="btn-leak-check-launcher">
                <ShieldQuestion className="w-4 h-4" />
                {size === "sm" && <span className="ml-1.5">Check Leaks</span>}
              </Button>
            </DropdownMenuTrigger>
          </TooltipTrigger>
          <TooltipContent side="top" className="max-w-xs text-xs">
            Opens breach-check sites pre-filled with this value. Only use on targets you are authorised to test.
          </TooltipContent>
        </Tooltip>

        <DropdownMenuContent align="end" className="w-52">
          <DropdownMenuLabel className="flex items-center gap-1.5 text-xs">
            <Globe className="w-3 h-3" />
            Breach Check: <span className="font-mono truncate max-w-[120px]">{value}</span>
          </DropdownMenuLabel>
          <DropdownMenuSeparator />

          {applicableSites.map((site) => (
            <DropdownMenuItem
              key={site.label}
              onClick={() => openSite(site)}
              className="text-xs cursor-pointer"
              data-testid={`leak-site-${site.label.toLowerCase().replace(/\s+/g, "-")}`}
            >
              <ExternalLink className="w-3 h-3 mr-2 text-muted-foreground" />
              {site.label}
            </DropdownMenuItem>
          ))}

          <DropdownMenuSeparator />
          <DropdownMenuItem onClick={copyAllUrls} className="text-xs cursor-pointer">
            <Copy className="w-3 h-3 mr-2 text-muted-foreground" />
            Copy all URLs
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </TooltipProvider>
  );
}
