/**
 * Benchmark evidence fixtures for deterministic 1-click live evaluation in browser.
 * Derived from the authoritative Recoverix test suite and ground-truth corpus.
 */

// Landing Page (Home) Evaluation Presets
export const FIXTURE_JSON = '{"case":"IR-99","status":"active","tags":["malware","network"';

export const FIXTURE_TXT =
  "Subject: Security Incident Escalation\nTo: Operations Team\n\n" +
  "\x00".repeat(48) +
  "Action Taken: Contained affected workstation and isolated host.\n";

export const FIXTURE_CSV =
  "id,name,role,department\n" +
  "101,Alice Vance,Forensics Lead,Incident Response\n" +
  "102,Bob Miller,Security Analyst,SOC\n" +
  "103,Charlie Chen,Malware Engineer,Reverse Eng\n";

export const FIXTURE_XML =
  '<?xml version="1.0" encoding="UTF-8"?>\n' +
  '<audit_log id="LOG-884">\n' +
  '  <source>firewall-edge-01</source>\n' +
  '  <event status="blocked">Unauthorized access attempt</event>\n';

export const FIXTURE_JPEG_B64 = "/9j/wAARCAAQABADAREAAhEBAxEB/9oADAMBAAIRAxEAPwAAf//Z";

// Setup Page Contextual Investigation Presets
export const FIXTURE_INCIDENT_JSON =
  '{"case":"IR-99","status":"active","tags":["malware","network"';

export const FIXTURE_INCIDENT_TXT =
  "Subject: Incident Escalation\nTo: Security Operations Center\n\n" +
  "\x00".repeat(48) +
  "Action Taken: Contained infected workstation and quarantined IP.\n";

export const FIXTURE_CLEAN_TXT =
  "Line 1: System initialization sequence completed.\n" +
  "Line 2: User admin authentication validated from 192.168.1.10.\n" +
  "Line 3: Routine audit log integrity verified across all nodes.\n";

export const FIXTURE_STAFF_CSV =
  "id,name,role,department\n" +
  "101,Alice Vance,Chief Investigator,Forensics\n" +
  "102,Bob Miller,Security Analyst,SOC\n" +
  "103,Charlie Chen,Malware Engineer,Reverse Eng\n";

// Real 315-byte shuffled PDF binary (two real PDF fragments in reverse order)
export const FIXTURE_SHUFFLED_PDF_B64 =
  "ZG9iagozIDAgb2JqCjw8IC9UeXBlIC9QYWdlIC9QYXJlbnQgMiAwIFIgPj4KZW5kb2JqCnhyZWYKMCA0CjAwMDAwMDAwMDAgNjU1MzUgZiAKMDAwMDAwMDAwOSAwMDAwMCBuIAowMDAwMDAwMDUyIDAwMDAwIG4gCjAwMDAwMDAxMTggMDAwMDAgbiAKdHJhaWxlcgo8PCAvU2l6ZSA0IC9Sb290IDEgMCBSID4+CnN0YXJ0eHJlZgoxNzIKJSVFT0YKJVBERi0xLjQKMSAwIG9iago8PCAvVHlwZSAvQ2F0YWxvZyAvUGFnZXMgMiAwIFIgPj4KZW5kb2JqCjIgMCBvYmoKPDwgL1R5cGUgL1BhZ2VzIC9LaW5kcyBbXSAvQ291bnQgMSAvS2lkcyBbMyAwIFJdID4+CmVu";

// Real 39-byte valid JPEG binary (SOI/SOF0/SOS/EOI marker sequence)
export const FIXTURE_PHOTO_JPEG_B64 =
  "/9j/wAARCAAQABADAREAAhEBAxEB/9oADAMBAAIRAxEAPwAAf//Z";
