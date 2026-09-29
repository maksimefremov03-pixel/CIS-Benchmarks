#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <winreg.h>

using namespace std;

struct CISCheck {
    string id;
    string description;
    bool success;
};

class CISAuditor {
private:
    vector<CISCheck> checks;
    int totalChecks;
    int successfulChecks;

public:
    CISAuditor() : totalChecks(0), successfulChecks(0) {
        InitializeChecks();
    }

    void InitializeChecks() {
        checks = {
            {"17.2.3", "Audit User Account Management", false},
            {"18.10.42.10.2", "Turn off real-time protection", false},
            {"5.1", "'Bluetooth Audio Gateway Service (BTAGService)", false},
            {"18.10.65.4", "Turn off the offer to update to the latest version of Windows", false},
            {"18.10.9.2.11", "Configure use of hardware-based encryption for operating system drives", false},
            {"18.10.56.3.3.3", "Do not allow drive redirection", false},
            {"2.3.10.2", "Network access: Do not allow anonymous enumeration of SAM accounts", false},
            {"18.10.56.3.10.1", "Set time limit for active but idle Remote Desktop Services sessions", false},
            {"18.10.9.1.9", "Choose how BitLocker-protected fixed drives can be recovered : Do not enable BitLocker until recovery information is stored to AD DS for fixed data drives", false},
            {"2.3.17.5", "User Account Control: Only elevate UIAccess applications that are installed in secure locations", false},
            {"9.1.7", "Windows Firewall: Domain: Logging: Log successful connections", false},
            {"9.2.6", "Windows Firewall: Private: Logging: Log dropped packets", false},
            {"18.6.4.1", "Configure NetBIOS settings", false},
            {"18.9.19.3", "Configure registry policy processing: Process even if the Group Policy objects have not changed", false},
            {"18.10.13.1", "Require pin for pairing", false}
        };
        totalChecks = checks.size();
    }

    bool CheckRegistryValue(HKEY hKey, const string& subKey, const string& valueName, DWORD expectedValue) {
        HKEY key;
        DWORD data;
        DWORD dataSize = sizeof(DWORD);
        
        if (RegOpenKeyExA(hKey, subKey.c_str(), 0, KEY_READ, &key) == ERROR_SUCCESS) {
            if (RegQueryValueExA(key, valueName.c_str(), NULL, NULL, (LPBYTE)&data, &dataSize) == ERROR_SUCCESS) {
                RegCloseKey(key);
                return data == expectedValue;
            }
            RegCloseKey(key);
        }
        return false;
    }

    void RunAudit() {
        successfulChecks = 0;

        // 17.2.3
        checks[0].success = CheckRegistryValue(HKEY_LOCAL_MACHINE, 
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit", "AuditUserAccountManagement", 3);

        // 18.10.42.10.2
        checks[1].success = CheckRegistryValue(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "DisableRealtimeMonitoring", 0);

        // 5.1
        checks[2].success = CheckRegistryValue(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Services\\BTAGService", "Start", 4);

        // 18.10.65.4
        checks[3].success = CheckRegistryValue(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Policies\\Microsoft\\WindowsStore", "DisableOSUpgrade", 1);

        // 18.10.9.2.11
        checks[4].success = CheckRegistryValue(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Policies\\Microsoft\\FVE", "OSHardwareEncryption", 0);
        
        // 18.10.56.3.3.3
        checks[5].success = CheckRegistryValue(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services", "fDisableCdm", 1);

        // 2.3.10.2
        checks[6].success = CheckRegistryValue(HKEY_LOCAL_MACHINE,
            "SYSTEM\\CurrentControlSet\\Control\\Lsa", "RestrictAnonymousSAM", 1);

        // 18.10.56.3.10.1
        checks[7].success = CheckRegistryValue(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services", "MaxIdleTime", 900000);

        // 18.10.9.1.9
        checks[8].success = CheckRegistryValue(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Policies\\Microsoft\\FVE", "FDVRequireActiveDirectoryBackup", 0);

        // Ïðîâåðêà 2.3.17.5
        checks[9].success = CheckRegistryValue(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "EnableSecureUIAPaths", 1);

        // 9.1.7
        checks[10].success = CheckRegistryValue(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\DomainProfile\\Logging", "LogSuccessfulConnections", 1);

        // 9.2.6
        checks[11].success = CheckRegistryValue(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\PrivateProfile\\Logging", "LogDroppedPackets", 1);

        // 18.6.4.1
        checks[12].success = CheckRegistryValue(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", "EnableNetbios", 0);

        // 18.9.19.3
        checks[13].success = CheckRegistryValue(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Policies\\Microsoft\\Windows\\Group Policy\\{35378EAC - 683F - 11D2 - A89A - 00C04FBBCFA2}", "NoGPOListChanges", 0);
        
        // 18.10.13.1
        checks[14].success = CheckRegistryValue(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Policies\\Microsoft\\Windows\\Connect", "RequirePinForPairing", 1);

        for (size_t i = 0; i < checks.size(); i++) if (checks[i].success) successfulChecks++;
    }

    void DisplayResults() {
        cout << "=== Àíàëèç è àóäèò êîíôèãóðàöèè ÎÑ Windows ===" << endl << endl;
        
        cout << "ÐÅÇÓËÜÒÀÒÛ:" << endl;
        cout << "Âñåãî ïðîâåðîê: " << totalChecks << endl;
        cout << "Ñîîòâåòñòâóåò: " << successfulChecks << endl;
        cout << "Íå ñîîòâåòñòâóåò: " << (totalChecks - successfulChecks) << endl;
        cout << "Îöåíêà ñîîòâåòñòâèÿ: " << ((double)successfulChecks / totalChecks * 100) << "%" << endl << endl;

        cout << "ÄÅÒÀËÜÍÛÅ ÐÅÇÓËÜÒÀÒÛ:" << endl;
        cout << string(80, '-') << endl;
        
        for (const auto& check : checks) {
            cout << "ID: " << check.id << endl;
            cout << "Îïèñàíèå: " << check.description << endl;
            cout << "Ñòàòóñ: " << (check.success ? "ÑÎÎÒÂÅÒÑÒÂÓÅÒ" : "ÍÅ ÑÎÎÒÂÅÒÑÒÂÓÅÒ") << endl;
            cout << string(80, '-') << endl;
        }
    }
};

int main() {
    SetConsoleCP(1251);
    SetConsoleOutputCP(1251);

    CISAuditor auditor;
    auditor.RunAudit();
    auditor.DisplayResults();

    return 0;
}