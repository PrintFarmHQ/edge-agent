package printeradapter

import "strings"

var supportCatalog = []ProfileDescriptor{
	{
		Key:               "moonraker.snapmaker_u1",
		Family:            "moonraker",
		DisplayName:       "Snapmaker U1",
		SupportTier:       SupportTierOfficial,
		SupportedPanels:   []PanelKey{PanelStatus, PanelQueue, PanelCamera, PanelControls, PanelFiles},
		DocumentationSlug: "moonraker-snapmaker-u1",
	},
	{
		Key:               "moonraker.generic",
		Family:            "moonraker",
		DisplayName:       "Generic Moonraker / Klipper",
		SupportTier:       SupportTierGeneric,
		SupportedPanels:   []PanelKey{PanelStatus, PanelQueue, PanelCamera, PanelControls, PanelFiles},
		DocumentationSlug: "moonraker-klipper-generic",
	},
	{
		Key:               "bambu.p1_family",
		Family:            "bambu",
		DisplayName:       "Bambu P1 Family",
		SupportTier:       SupportTierOfficial,
		SupportedPanels:   []PanelKey{PanelStatus, PanelQueue, PanelCamera, PanelControls, PanelFiles},
		DocumentationSlug: "bambu-p1-family",
	},
	{
		Key:               "bambu.generic",
		Family:            "bambu",
		DisplayName:       "Generic Bambu",
		SupportTier:       SupportTierExperimental,
		SupportedPanels:   []PanelKey{PanelStatus, PanelQueue, PanelCamera, PanelControls, PanelFiles},
		DocumentationSlug: "bambu-generic",
	},
	{
		Key:               "unsupported.unknown_adapter",
		Family:            "unknown",
		DisplayName:       "Unsupported printer",
		SupportTier:       SupportTierUnsupported,
		SupportedPanels:   []PanelKey{PanelStatus},
		UnsupportedReason: "unsupported_printer",
		DocumentationSlug: "unsupported-printer",
	},
}

func Catalog() []ProfileDescriptor {
	out := make([]ProfileDescriptor, len(supportCatalog))
	copy(out, supportCatalog)
	return out
}

func ResolveProfile(binding Binding, snapshot RuntimeSnapshot) ProfileDescriptor {
	family := normalizeFamily(binding.AdapterFamily)
	modelHint := normalizeModelHint(snapshot.DetectedModelHint)

	switch family {
	case "moonraker":
		if strings.Contains(modelHint, "snapmaker u1") {
			return supportCatalog[0]
		}
		return supportCatalog[1]
	case "bambu":
		if strings.Contains(modelHint, "p1s") || strings.Contains(modelHint, "p1p") || strings.Contains(modelHint, "p1") {
			return supportCatalog[2]
		}
		return supportCatalog[3]
	default:
		return supportCatalog[4]
	}
}

func normalizeFamily(raw string) string {
	value := strings.TrimSpace(strings.ToLower(raw))
	switch value {
	case "klipper":
		return "moonraker"
	default:
		return value
	}
}

func normalizeModelHint(raw string) string {
	return strings.TrimSpace(strings.ToLower(raw))
}
