import Foundation

class PhishingHeuristics {
    private let blocklist: Set<String> = ["malware.wicar.org", "eicar.org"]
    private let brands = ["paypal", "apple", "microsoft", "google", "amazon", "netflix", "facebook"]

    func evaluateDomain(_ domain: String) -> (phishing: Bool, reason: String?) {
        let d = domain.lowercased().trimmingCharacters(in: .whitespaces)

        if blocklist.contains(d) {
            return (true, "domain is blocklisted")
        }

        // Homograph attack detection
        let asciiCount = d.unicodeScalars.filter { $0.value < 128 }.count
        if d.count > 0 {
            let ratio = Double(asciiCount) / Double(d.count)
            if ratio < 0.8 {
                return (true, "homograph attack suspected")
            }
        }

        // Excessive subdomain depth
        let labels = d.components(separatedBy: ".")
        if labels.count >= 6 {
            return (true, "excessive subdomain depth")
        }

        // Brand impersonation
        let tld = labels.suffix(2).joined(separator: ".")
        for brand in brands {
            if d.contains(brand) && !tld.hasSuffix("\(brand).com") {
                return (true, "brand impersonation: \(brand)")
            }
        }

        return (false, nil)
    }
}
