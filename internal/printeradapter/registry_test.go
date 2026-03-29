package printeradapter

import "testing"

func TestResolveProfileMatchesSnapmakerU1Profile(t *testing.T) {
	profile := ResolveProfile(
		Binding{PrinterID: 1, AdapterFamily: "moonraker", EndpointURL: "http://moonraker.local:7125"},
		RuntimeSnapshot{DetectedModelHint: "Snapmaker U1"},
	)
	if profile.Key != "moonraker.snapmaker_u1" {
		t.Fatalf("profile key = %q, want moonraker.snapmaker_u1", profile.Key)
	}
	if profile.SupportTier != SupportTierOfficial {
		t.Fatalf("support tier = %q, want official", profile.SupportTier)
	}
	if len(profile.SupportedPanels) == 0 || profile.SupportedPanels[len(profile.SupportedPanels)-1] != PanelFiles {
		t.Fatalf("supported panels = %#v, want files panel included", profile.SupportedPanels)
	}
}

func TestResolveProfileFallsBackToGenericMoonraker(t *testing.T) {
	profile := ResolveProfile(
		Binding{PrinterID: 1, AdapterFamily: "klipper", EndpointURL: "http://moonraker.local:7125"},
		RuntimeSnapshot{DetectedModelHint: "Voron 2.4"},
	)
	if profile.Key != "moonraker.generic" {
		t.Fatalf("profile key = %q, want moonraker.generic", profile.Key)
	}
	if profile.SupportTier != SupportTierGeneric {
		t.Fatalf("support tier = %q, want generic", profile.SupportTier)
	}
}

func TestResolveProfileFallsBackToUnsupportedForUnknownAdapter(t *testing.T) {
	profile := ResolveProfile(
		Binding{PrinterID: 1, AdapterFamily: "mystery", EndpointURL: "mystery://printer-1"},
		RuntimeSnapshot{DetectedModelHint: "Unknown"},
	)
	if profile.Key != "unsupported.unknown_adapter" {
		t.Fatalf("profile key = %q, want unsupported.unknown_adapter", profile.Key)
	}
	if profile.SupportTier != SupportTierUnsupported {
		t.Fatalf("support tier = %q, want unsupported", profile.SupportTier)
	}
	if profile.UnsupportedReason != "unsupported_printer" {
		t.Fatalf("unsupported reason = %q, want unsupported_printer", profile.UnsupportedReason)
	}
}
