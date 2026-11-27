package deco

import (
	"encoding/base64"
	"strings"

	"github.com/gnacho/netpulse/agent/probe"
)

// The Deco API is a flat tree of named sections. Each call to api() returns
// one section's JSON object; payload.go keeps only the fields the neutral
// payload can express and discards the rest on purpose. In particular the
// wlan sections carry the Wi-Fi passphrase (base64) and every struct here
// omits that field, so a leaked credential can never reach the payload, the
// logs or the server.

// unit is one Deco in the mesh (device.device_list).
type unit struct {
	DeviceID    string   `json:"device_id"`
	MAC         string   `json:"mac"`
	Role        string   `json:"role"` // "master"|"slave"
	DeviceModel string   `json:"device_model"`
	SoftwareVer string   `json:"software_ver"`
	IP          string   `json:"ip"`
	InetStatus  string   `json:"inet_status"`
	Connection  []string `json:"connection_type"` // ["wired"]|[]
	BSSID2G     string   `json:"bssid_2g"`
	BSSID5G     string   `json:"bssid_5g"`
	CustomNick  string   `json:"custom_nickname"` // base64 display name
}

// meshClient is one LAN client (device.client_list).
type meshClient struct {
	MAC    string `json:"mac"`
	IP     string `json:"ip"`
	Name   string `json:"name"` // base64 display name
	Online bool   `json:"online"`
	Linked struct {
		SignalLevel struct {
			Band24 int `json:"band2_4"`
			Band5  int `json:"band5"`
		} `json:"signal_level"`
		Connection []string `json:"connection_type"` // ["wired"]|["band5"]|["band2_4"]
		DeviceID   string   `json:"device_id"`
	} `json:"linked_device_info"`
}

// wlanHost is one SSID profile (wlan.bandN.host). Only the fields that are
// safe and useful are read; the "password" member is never declared.
type wlanHost struct {
	SSID           string `json:"ssid"` // base64
	Enable         bool   `json:"enable"`
	EncryptionMode string `json:"encryption_mode"`
}

type wlan struct {
	Band24 struct {
		Host     wlanHost `json:"host"`
		Backhaul struct {
			Channel int `json:"channel"`
		} `json:"backhaul"`
	} `json:"band2_4"`
	Band51 struct {
		Host     wlanHost `json:"host"`
		Backhaul struct {
			Channel int `json:"channel"`
		} `json:"backhaul"`
	} `json:"band5_1"`
}

type ipInfo struct {
	IP      string `json:"ip"`
	Mask    string `json:"mask"`
	Gateway string `json:"gateway"`
	DNS1    string `json:"dns1"`
	DNS2    string `json:"dns2"`
}

type wanV4 struct {
	Wan struct {
		DialType string `json:"dial_type"`
		IPInfo   ipInfo `json:"ip_info"`
	} `json:"wan"`
	Lan struct {
		IPInfo ipInfo `json:"ip_info"`
	} `json:"lan"`
}

// b64 decodes a Deco base64 display string, returning "" for anything that
// is not valid base64 so a malformed field degrades to "no name" instead of
// erroring the whole poll.
func b64(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	out, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return ""
	}
	return string(out)
}

// macNorm upper-cases a Deco MAC ("B0-19-21-88-4E-D4" -> "B01921884ED4") to
// the key form the rest of the payload uses.
func macNorm(s string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), "-", ""))
}

// bandName maps a Deco connection band to the payload's band label.
func bandName(band string) string {
	switch band {
	case "band2_4":
		return "2.4 GHz"
	case "band5":
		return "5 GHz"
	default:
		return ""
	}
}

// ssidForBand returns the (decoded) SSID of the band a client is on, so the
// payload can carry the SSID per station. "" when the band is unknown or the
// wlan section is absent.
func ssidForBand(wl *wlan, band string) string {
	if wl == nil {
		return ""
	}
	switch band {
	case "5 GHz":
		return b64(wl.Band51.Host.SSID)
	case "2.4 GHz":
		return b64(wl.Band24.Host.SSID)
	default:
		return ""
	}
}

// signalDbm approximates a Deco 0-3 signal level as dBm. Deco only exposes
// four discrete bars, not a true RSSI, so the values are representative
// midpoints the UI can order and display, not a measurement.
func signalDbm(level int) int {
	switch level {
	case 3:
		return -50
	case 2:
		return -60
	case 1:
		return -70
	default:
		return -80
	}
}

func protoName(dial string) string {
	switch dial {
	case "dynamic_ip":
		return "dhcp"
	case "static_ip":
		return "static"
	case "pppoe":
		return "pppoe"
	default:
		return dial
	}
}

// buildPayload assembles the neutral payload from the sections that the
// firmware answers. units is required (the mesh identity); the rest are
// optional and each degrades to "section absent" when empty.
func buildPayload(units []unit, clients []meshClient, wl *wlan, wan *wanV4) *probe.PayloadData {
	data := &probe.PayloadData{}

	// --- System: the mesh is one logical router; the master unit is its
	// identity and the other units are its radios/ports.
	var master *unit
	for i := range units {
		if units[i].Role == "master" {
			master = &units[i]
			break
		}
	}
	if master == nil && len(units) > 0 {
		master = &units[0]
	}

	ifaceMACs := make([]string, 0, len(units)*2)
	seenMAC := map[string]bool{}
	addMAC := func(m string) {
		m = macNorm(m)
		if m != "" && !seenMAC[m] {
			seenMAC[m] = true
			ifaceMACs = append(ifaceMACs, m)
		}
	}

	sys := &probe.SystemData{}
	if master != nil {
		model := strings.TrimSpace(master.DeviceModel)
		if model != "" {
			model = "Deco " + model
		} else {
			model = "Deco"
		}
		sys.Board = &probe.BoardInfo{
			Model:    model,
			Hostname: b64(master.CustomNick),
			System:   "deco",
		}
		if master.SoftwareVer != "" {
			sys.Board.Release.Version = master.SoftwareVer
			sys.Board.Release.Description = model + " " + master.SoftwareVer
		}
		sys.BridgeMAC = macNorm(master.MAC)
	}

	// Backhaul: how the mesh reaches its WAN. A slave wired back to the
	// master is the common cable backhaul; otherwise the units are
	// wireless-bridged.
	if len(units) > 1 {
		backhaul := "wifi"
		for i := range units {
			if units[i].Role != "master" && contains(units[i].Connection, "wired") {
				backhaul = "cable"
				break
			}
		}
		sys.Backhaul = backhaul
	}
	data.System = sys

	// IfaceMACs: every unit MAC plus its per-band BSSIDs, so the server can
	// seed its own-BSSID set and stop counting the mesh's networks as
	// neighbours.
	for i := range units {
		u := &units[i]
		addMAC(u.MAC)
		addMAC(u.BSSID2G)
		addMAC(u.BSSID5G)
	}
	if len(ifaceMACs) > 0 {
		data.System.IfaceMACs = ifaceMACs
	}

	// --- Wireless: radios from the SSID profiles, clients from client_list.
	radios := []probe.Radio{}
	if wl != nil {
		if wl.Band24.Host.Enable {
			radios = append(radios, probe.Radio{Name: "2.4 GHz", Channel: wl.Band24.Backhaul.Channel})
		}
		if wl.Band51.Host.Enable {
			radios = append(radios, probe.Radio{Name: "5 GHz", Channel: wl.Band51.Backhaul.Channel})
		}
	}

	wirelessClients := map[string]probe.WirelessClient{}
	arp := map[string]string{}
	dhcpLeases := []probe.DhcpLease{}

	// unitByID maps linked_device_info.device_id -> unit so a wireless client
	// can be tied to the specific mesh node it is associated with. This is what
	// the server's per-router client view keys on: Iface carries the associated
	// unit's identity (one of IfaceMACs), so the UI can split the client list
	// into one per Deco in the mesh.
	unitByID := map[string]*unit{}
	for i := range units {
		if units[i].DeviceID != "" {
			unitByID[units[i].DeviceID] = &units[i]
		}
	}

	for i := range clients {
		c := &clients[i]
		mac := macNorm(c.MAC)
		if mac == "" {
			continue
		}
		name := b64(c.Name)

		// Every client that has an IP is a known host: record it in ARP and,
		// if it carries a name, as a DHCP reservation so static-named clients
		// are not bare MACs.
		if c.IP != "" {
			arp[mac] = c.IP
			if name != "" {
				dhcpLeases = append(dhcpLeases, probe.DhcpLease{MAC: mac, IP: c.IP, Hostname: name})
			}
		}

		// Wireless clients only (wired clients are not a radio association).
		band := ""
		if len(c.Linked.Connection) > 0 {
			band = bandName(c.Linked.Connection[0])
		}
		if band == "" || !c.Online {
			continue
		}
		level := 0
		if band == "5 GHz" {
			level = c.Linked.SignalLevel.Band5
		} else {
			level = c.Linked.SignalLevel.Band24
		}
		wc := probe.WirelessClient{
			SignalDbm: signalDbm(level),
			Band:      band,
			SSID:      ssidForBand(wl, band),
		}
		if u := unitByID[c.Linked.DeviceID]; u != nil {
			wc.Iface = macNorm(u.MAC)
		}
		wirelessClients[mac] = wc
	}

	// Count clients per radio band for the radio summary.
	for _, wc := range wirelessClients {
		for r := range radios {
			if radios[r].Name == wc.Band {
				radios[r].Clients++
			}
		}
	}

	data.Wireless = &probe.WirelessData{
		Clients: wirelessClients,
		Radios:  radios,
	}
	if len(arp) > 0 {
		data.Arp = arp
	}
	if len(dhcpLeases) > 0 {
		data.DHCP = &probe.DHCPData{Leases: dhcpLeases}
	}

	// --- Wan: the master's uplink.
	if wan != nil && wan.Wan.IPInfo.IP != "" {
		dns := []string{}
		if wan.Wan.IPInfo.DNS1 != "" {
			dns = append(dns, wan.Wan.IPInfo.DNS1)
		}
		if wan.Wan.IPInfo.DNS2 != "" {
			dns = append(dns, wan.Wan.IPInfo.DNS2)
		}
		data.Wan = &probe.WanInfo{
			Proto:   protoName(wan.Wan.DialType),
			Device:  "wan",
			IP:      wan.Wan.IPInfo.IP,
			Gateway: wan.Wan.IPInfo.Gateway,
			DNS:     dns,
		}
	}

	return data
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// The *Resp types wrap one section of the Deco API. Each call answers
// {"error_code":0,"result":{...}}; the poller unmarshals into these and
// hands the inner value to buildPayload.
type deviceListResp struct {
	ErrorCode int `json:"error_code"`
	Result    struct {
		DeviceList []unit `json:"device_list"`
	} `json:"result"`
}

type clientListResp struct {
	ErrorCode int `json:"error_code"`
	Result    struct {
		ClientList []meshClient `json:"client_list"`
	} `json:"result"`
}

type wlanResp struct {
	ErrorCode int  `json:"error_code"`
	Result    wlan `json:"result"`
}

type wanV4Resp struct {
	ErrorCode int   `json:"error_code"`
	Result    wanV4 `json:"result"`
}
