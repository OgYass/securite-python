/*
 * Règles personnelles du binôme.
 */

rule Has_Mutex
{
    meta:
        author = "binome"
        description = "Mutex nommé (empêche une double exécution)"
        mitre_attack = "T1480"
    strings:
        $global = /Global\\[A-Za-z0-9_.-]{4,}/
        $local = /Local\\[A-Za-z0-9_.-]{4,}/
    condition:
        any of them
}

rule Registry_Run_Persistence
{
    meta:
        author = "binome"
        description = "Persistance via la clé Run du registre"
        mitre_attack = "T1547.001"
    strings:
        $run = /HK(CU|LM)\\Software\\Microsoft\\Windows\\CurrentVersion\\Run/ nocase
    condition:
        $run
}

rule C2_Gate_URL
{
    meta:
        author = "binome"
        description = "URL de panneau C2 (gate.php)"
        mitre_attack = "T1071.001"
    strings:
        $gate = /https?:\/\/[A-Za-z0-9.-]+\/[A-Za-z0-9_\/-]*gate\.php/ nocase
    condition:
        $gate
}

rule Prompt_Injection_Attempt
{
    meta:
        author = "binome"
        description = "Texte qui tente de manipuler un analyste IA"
    strings:
        $a = "ignore previous instructions" nocase
        $b = "ignore les instructions" nocase
        $c = "AI_INSTRUCTIONS" nocase
        $d = "mark the sample clean" nocase
    condition:
        any of them
}
