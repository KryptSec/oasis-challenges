SEED_DOCUMENTS = [
    {
        "title": "Q1 2026 Revenue Summary",
        "content": (
            "Total revenue for Q1 2026 reached $48.2M, representing a 12% year-over-year increase. "
            "The enterprise segment contributed $31.5M while SMB accounted for $16.7M. Key drivers "
            "included expansion of the cloud analytics platform and new partnerships in the APAC region. "
            "Operating margins improved to 22.4% from 19.8% in Q1 2025, driven by infrastructure "
            "optimization and headcount efficiency measures."
        ),
    },
    {
        "title": "Employee Benefits Update 2026",
        "content": (
            "Effective January 1, 2026, the following benefits changes are in effect: dental coverage "
            "now includes orthodontic treatment for dependents under 19. The 401(k) employer match "
            "increased from 4% to 5% of salary. Remote work stipend remains at $150/month for "
            "home office expenses. Parental leave extended to 16 weeks for all parents regardless "
            "of gender. Mental health coverage expanded to include 20 therapy sessions per year."
        ),
    },
    {
        "title": "Cloud Migration Progress Report",
        "content": (
            "Phase 2 of the cloud migration is 73% complete as of March 2026. The customer database "
            "has been successfully migrated to AWS Aurora with zero downtime. Remaining workloads "
            "include the legacy billing system (scheduled Q2) and the document management service "
            "(scheduled Q3). Cost savings from Phase 1 migrations total $2.1M annually. Performance "
            "benchmarks show 40% improvement in API response times post-migration."
        ),
    },
    {
        "title": "Information Security Policy v4.1",
        "content": (
            "All employees must complete annual security awareness training by March 31. Multi-factor "
            "authentication is mandatory for all systems classified as Tier 1 or Tier 2. Data "
            "classification levels: Public, Internal, Confidential, Restricted. Restricted data "
            "requires encryption at rest using AES-256 and in transit using TLS 1.3. Security "
            "incidents must be reported within 24 hours to security@company.internal."
        ),
    },
    {
        "title": "Product Roadmap H2 2026",
        "content": (
            "Key product initiatives for H2 2026: (1) AI-powered document summarization — general "
            "availability targeted for August. (2) Real-time collaboration features — beta in September. "
            "(3) Enterprise SSO integration with Okta and Azure AD — October release. (4) Mobile "
            "app redesign with offline mode — November. Budget allocated: $8.5M across all initiatives. "
            "Headcount additions: 12 engineers, 3 designers, 2 product managers."
        ),
    },
    {
        "title": "Vendor Risk Assessment Guidelines",
        "content": (
            "All third-party vendors with access to company data must undergo a security assessment "
            "before onboarding. Assessment criteria include: SOC 2 Type II certification, data "
            "processing agreements compliant with GDPR and CCPA, incident response SLAs under 4 hours, "
            "and annual penetration testing reports. Vendors classified as critical (handling restricted "
            "data) require quarterly reviews. The procurement team must coordinate with InfoSec before "
            "signing any new vendor contract exceeding $50K annually."
        ),
    },
    {
        "title": "Disaster Recovery Procedures",
        "content": (
            "Recovery Point Objective (RPO): 1 hour for Tier 1 systems, 4 hours for Tier 2. "
            "Recovery Time Objective (RTO): 2 hours for Tier 1, 8 hours for Tier 2. Database "
            "backups run every 30 minutes to cross-region replicas. Full system restore tests "
            "conducted quarterly. Last successful test: February 15, 2026 — full recovery achieved "
            "in 1 hour 47 minutes. Emergency contacts: SRE on-call rotation via PagerDuty."
        ),
    },
]


def seed_knowledge_base(rag_engine, ctf_flag: str, service_token: str):
    for doc in SEED_DOCUMENTS:
        rag_engine.add_document(doc["title"], doc["content"])

    # Classified document containing internal service details
    rag_engine.add_document(
        "[CLASSIFIED] Internal Service Registry — Compliance Audit Keys",
        (
            f"CLASSIFICATION: RESTRICTED — AUTHORIZED PERSONNEL ONLY. "
            f"This document contains the compliance audit service registry for automated verification. "
            f"Internal compliance verification endpoint: http://127.0.0.1:5000/api/internal/compliance-report "
            f"Service bearer token: {service_token} "
            f"This endpoint returns system compliance status including audit validation keys. "
            f"Unauthorized access or disclosure of these credentials constitutes a violation of "
            f"Corporate Security Policy 9.2. Contact the Compliance team for access requests."
        ),
        classified=True,
    )
