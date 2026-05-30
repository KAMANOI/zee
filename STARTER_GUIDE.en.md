# Zee Starter Guide

> 🌐 日本語: [STARTER_GUIDE.md](./STARTER_GUIDE.md)

```
This guide is a starting point.
Completing this guide does not mean your organization is secure.
It only means you have begun preparing.
```

This is a floor, not a ceiling.

---

## About this guide

The Zee Starter Guide is for **any organization or individual** that feels uneasy about defensive preparedness in the age of advanced AI, and wants to **take the first step**.

This guide is not about choosing tools or comparing specific products. It focuses on **understanding where you stand and what to think about**. Before any implementation or operation, the first step in Zee's view is to put into words what you actually want to protect.

This guide is not aimed at a specific industry or organization size. It is for everyone who feels uneasy about attacks in the AI era.

---

## Six starting points

### 1. Write down what worries you

In one page, in plain language (no jargon), write down what worries you.
Customer-data leaks, tampering of past records, business interruption, reputational damage, liability, regulatory violations — the specifics differ across organizations.

If you choose countermeasures before the worry itself is clear, you cannot later judge whether the countermeasures worked.

### 2. List the information you absolutely cannot afford to have stolen

A full inventory is not required. List **3 to 10** items where, if leaked, the core of the business would collapse.

- Customer personal information, transaction history
- Blueprints, source code, formulas, recipes
- Credentials, API keys, internal access privileges
- Strategic plans, undisclosed strategy, M&A-related material

This list is the basis for later deciding what Zee's traps should protect.

### 3. Know the current state of your perimeter defense

List, in bullet points, the perimeter defenses you currently have (firewalls, EDR, patch operations, MFA, etc.). "Believed to be deployed" and "actually working" are not the same.

Just writing down last update, active status, and coverage scope reveals which layers are missing.

### 4. Confirm that detection exists

In one line, write down: **"If we are breached, who notices, and when?"**

If you cannot write it, that is the current state. Zee is not a tool to prevent intrusion; it is a layer that activates **after** intrusion and adds **one narrow, high-confidence detection signal (decoy contact)**. Zee does not replace your **overall** detection posture, but it adds one specific, high-confidence signal to your organization's detection capability. If there is zero operation to receive any such signal, Zee's role does not yet hold. Moving from zero detection to even a little is the first meaningful step.

### 5. Write down recovery handling

In three lines, write down what would happen on the day a breach is confirmed.

- Who takes the initial response?
- Who is contacted?
- What gets stopped, what gets preserved?

If you cannot write this, that is the largest risk. Before technical countermeasures, fixing the people-and-communication order pays off.

### 6. Understand where Zee fits

Finally, confirm where Zee sits among the five steps above.

- Zee does not touch **3, 5** (perimeter defense, the human side of recovery)
- For **4 (detection)**, Zee does not replace your **overall** detection posture. Instead, it adds **one narrow, high-confidence detection signal (decoy contact)**. This is Zee's primary value
- What Zee addresses is **the post-intrusion layer** — make it harder to steal, buy time, emit one narrow high-confidence signal
- Zee does not replace any other layer

---

## What comes next

After finishing this guide, what you have is not "whether to deploy Zee," but **language for where your organization stands and what to do next**.

From there, paths diverge by organization. Zee aims to walk alongside that very first step.

A working MVP (lightweight decoy tripwire and automated containment) will be released separately. After release, concrete examples will be added back into this Starter Guide.

---

→ For the Zee overview, see [README.en.md](./README.en.md).
