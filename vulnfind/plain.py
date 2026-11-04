"""--plain: findings explained for people who don't work in security.

Each explanation answers three questions in everyday words: who could do what,
how bad that is for the business, and what to ask the developer to do.
"""

from __future__ import annotations

import re
from typing import Optional

from .models import Finding

BY_CWE = {
    "CWE-89": "Someone could type special text into your app that tricks your database into giving them, changing or deleting your data - including customer records and passwords.",
    "CWE-78": "Someone could make your server run any command they like, which usually means they take over the server completely.",
    "CWE-95": "Someone could make your app run their own code, which usually means a full takeover of the server.",
    "CWE-94": "Someone could inject their own commands into this automation, running code with access to your secrets.",
    "CWE-502": "Someone could send specially crafted data that, when your app opens it, runs their code on your server.",
    "CWE-1336": "Someone could inject template code that runs on your server.",
    "CWE-22": "Someone could read (or overwrite) files on your server they should never see, like configuration files with passwords.",
    "CWE-98": "Someone could make your site load and run a file of their choosing.",
    "CWE-918": "Someone could make your server send requests on their behalf - often to reach internal systems or steal cloud credentials.",
    "CWE-79": "Someone could plant malicious script in a page, so visitors' accounts or data can be stolen when they view it.",
    "CWE-601": "Your site can be used to send people to a malicious site while looking like a link to you - useful for phishing.",
    "CWE-798": "A password or key is written in the code. Anyone who sees the code (or the app's files) can use it.",
    "CWE-321": "A private key is stored where others can get it, so they can impersonate you or decrypt your data.",
    "CWE-538": "A file with sensitive information is exposed and could be downloaded or read by people who shouldn't have it.",
    "CWE-295": "Encrypted connections aren't being checked properly, so someone on the same network could read or change the traffic.",
    "CWE-319": "Information is sent without encryption, so anyone on the same network (e.g. public Wi-Fi) could read it.",
    "CWE-326": "An outdated, weaker form of encryption is still allowed.",
    "CWE-327": "An outdated, breakable form of encryption is used.",
    "CWE-328": "A weak scrambling method (hash) is used that can be reversed or forged with modern computers.",
    "CWE-338": "Values that must be unguessable (like reset tokens) are generated in a predictable way, so they can be guessed.",
    "CWE-306": "This part of the app can be used without logging in, even though it probably should require it.",
    "CWE-352": "Another website could make your logged-in users perform actions without realising it.",
    "CWE-384": "An attacker could fix a user's session in advance and then share that user's login.",
    "CWE-614": "Login cookies aren't fully protected, so they could be stolen and used to take over accounts.",
    "CWE-942": "Other websites are allowed to read data from your app on behalf of your logged-in users.",
    "CWE-693": "A standard browser protection is switched off or missing, making other attacks easier.",
    "CWE-1021": "Your page can be hidden inside another site to trick users into clicking things.",
    "CWE-250": "Something runs with more power (e.g. as administrator) than it needs, so any break-in becomes much worse.",
    "CWE-284": "Something is open to the whole internet that should be restricted.",
    "CWE-269": "An account or service has far more permissions than it needs.",
    "CWE-1104": "Software that's no longer supported or updated is in use, so newly discovered problems will never be fixed.",
    "CWE-1357": "Something you rely on isn't locked to a known version, so it can change underneath you.",
    "CWE-829": "Code from outside your control can run in your build or app with access to your secrets.",
    "CWE-200": "Your system reveals internal details that help attackers plan an attack.",
    "CWE-209": "Error pages show internal details that help attackers.",
    "CWE-548": "Anyone can browse the list of files in a folder on your site.",
    "CWE-290": "Others could send emails that look like they come from your domain (phishing).",
    "CWE-350": "A web address on your domain points to something that no longer exists - someone else could claim it and put their own content on your domain.",
    "CWE-308": "An account can be accessed with just a password; a phished or leaked password is enough to get in.",
    "CWE-732": "File permissions let anyone on the machine change these files.",
    "CWE-400": "The system can be overwhelmed or slowed down, causing outages.",
}


def explain(f: Finding) -> str:
    if f.category == "dependency" and f.extra.get("package"):
        pkg = f.extra["package"]
        base = (f"Your project uses {pkg} version {f.extra.get('version', '?')}, which has a publicly known security flaw "
                f"({f.rule_id}). Attackers actively look for apps using known-vulnerable versions.")
        if f.extra.get("kev"):
            base += " Criminals are already exploiting this one right now."
        if f.extra.get("fixed"):
            base += f" Ask the developer to upgrade it to {f.extra['fixed']} or newer."
        return base
    if f.category == "license":
        return "One of the libraries you use has a license that may legally require you to publish your own source code or stop using it. Check with whoever handles legal."
    text = BY_CWE.get(f.cwe or "")
    if not text:
        if f.category == "secret":
            text = BY_CWE["CWE-798"]
        elif f.rule_id.startswith(("WEB-SUBDOMAIN", "WEB-DANGLING")):
            text = BY_CWE["CWE-350"]
        else:
            text = re.split(r"(?<=\.)\s", f.description or f.title)[0]
    if f.extra.get("route_auth") is False:
        text += " This can be reached without logging in."
    impact = {"CRITICAL": "Treat this as urgent.", "HIGH": "This should be fixed soon.", "MEDIUM": "Worth fixing in the normal course of work.",
              "LOW": "Low risk on its own.", "INFO": "For awareness."}[f.severity.label]
    return f"{text} {impact}"
