FROM node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32 AS build

RUN corepack enable && corepack prepare pnpm@11.5.1 --activate
WORKDIR /app

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY apps/web/package.json apps/web/package.json
COPY packages/shared/package.json packages/shared/package.json
COPY packages/config/package.json packages/config/package.json
RUN pnpm install --frozen-lockfile

COPY apps/web apps/web
COPY packages/shared packages/shared
COPY packages/config packages/config
COPY assets assets

# The supplied public docs render canonical markdown via ?raw imports. Copy only
# these three engineering documents into the matching repository path; no other
# docs, private notes, archives or release records are included in the image.
COPY docs/engineering/openarc-engineering-source-of-truth.md docs/engineering/openarc-backend-architecture.md docs/engineering/openarc-frontend-architecture.md docs/engineering/

ARG COMMIT_SHA=local
ARG VITE_ENCRYPTED_WORKSPACE_ENABLED=false
ARG VITE_API_BOUNDARY_ENABLED=false
ARG VITE_ARC_OBSERVATION_ENABLED=false
ARG VITE_AGENT_REGISTRY_ENABLED=false
ENV VITE_COMMIT_SHA=${COMMIT_SHA}
ENV VITE_ENCRYPTED_WORKSPACE_ENABLED=${VITE_ENCRYPTED_WORKSPACE_ENABLED}
ENV VITE_API_BOUNDARY_ENABLED=${VITE_API_BOUNDARY_ENABLED}
ENV VITE_ARC_OBSERVATION_ENABLED=${VITE_ARC_OBSERVATION_ENABLED}
ENV VITE_AGENT_REGISTRY_ENABLED=${VITE_AGENT_REGISTRY_ENABLED}
ARG VITE_AGENT_JOBS_ENABLED=false
ENV VITE_AGENT_JOBS_ENABLED=${VITE_AGENT_JOBS_ENABLED}
ARG VITE_GATEWAY_EVIDENCE_ENABLED=false
ENV VITE_GATEWAY_EVIDENCE_ENABLED=${VITE_GATEWAY_EVIDENCE_ENABLED}
ARG VITE_GENERIC_AGENT_IMPORT_ENABLED=false
ARG VITE_INVESTIGATIONS_ENABLED=false
ENV VITE_INVESTIGATIONS_ENABLED=${VITE_INVESTIGATIONS_ENABLED}
RUN if [ "${VITE_INVESTIGATIONS_ENABLED}" = "true" ] && [ "${VITE_ENCRYPTED_WORKSPACE_ENABLED}" != "true" ]; then exit 1; fi
ENV VITE_GENERIC_AGENT_IMPORT_ENABLED=${VITE_GENERIC_AGENT_IMPORT_ENABLED}
ARG VITE_ACCOUNT_ACCESS_ENABLED=false
ENV VITE_ACCOUNT_ACCESS_ENABLED=${VITE_ACCOUNT_ACCESS_ENABLED}
RUN case "${VITE_ACCOUNT_ACCESS_ENABLED}" in true|false) ;; *) echo 'VITE_ACCOUNT_ACCESS_ENABLED must be exactly true or false' >&2; exit 1 ;; esac
RUN if [ "${VITE_ACCOUNT_ACCESS_ENABLED}" = "true" ] && [ "${VITE_API_BOUNDARY_ENABLED}" != "true" ]; then echo 'VITE_ACCOUNT_ACCESS_ENABLED=true requires VITE_API_BOUNDARY_ENABLED=true' >&2; exit 1; fi
ARG VITE_TENANT_READS_ENABLED=false
ENV VITE_TENANT_READS_ENABLED=${VITE_TENANT_READS_ENABLED}
RUN case "${VITE_TENANT_READS_ENABLED}" in true|false) ;; *) echo 'VITE_TENANT_READS_ENABLED must be exactly true or false' >&2; exit 1 ;; esac
RUN if [ "${VITE_TENANT_READS_ENABLED}" = "true" ] && { [ "${VITE_ACCOUNT_ACCESS_ENABLED}" != "true" ] || [ "${VITE_API_BOUNDARY_ENABLED}" != "true" ]; }; then echo 'VITE_TENANT_READS_ENABLED=true requires VITE_ACCOUNT_ACCESS_ENABLED=true and VITE_API_BOUNDARY_ENABLED=true' >&2; exit 1; fi
ARG VITE_TENANT_WRITES_ENABLED=false
ENV VITE_TENANT_WRITES_ENABLED=${VITE_TENANT_WRITES_ENABLED}
RUN case "${VITE_TENANT_WRITES_ENABLED}" in true|false) ;; *) echo 'VITE_TENANT_WRITES_ENABLED must be exactly true or false' >&2; exit 1 ;; esac
RUN if [ "${VITE_TENANT_WRITES_ENABLED}" = "true" ] && { [ "${VITE_TENANT_READS_ENABLED}" != "true" ] || [ "${VITE_ACCOUNT_ACCESS_ENABLED}" != "true" ] || [ "${VITE_API_BOUNDARY_ENABLED}" != "true" ]; }; then echo 'VITE_TENANT_WRITES_ENABLED=true requires VITE_TENANT_READS_ENABLED=true, VITE_ACCOUNT_ACCESS_ENABLED=true and VITE_API_BOUNDARY_ENABLED=true' >&2; exit 1; fi
ARG VITE_MACHINE_CREDENTIAL_MANAGEMENT_ENABLED=false
ENV VITE_MACHINE_CREDENTIAL_MANAGEMENT_ENABLED=${VITE_MACHINE_CREDENTIAL_MANAGEMENT_ENABLED}
RUN case "${VITE_MACHINE_CREDENTIAL_MANAGEMENT_ENABLED}" in true|false) ;; *) echo 'VITE_MACHINE_CREDENTIAL_MANAGEMENT_ENABLED must be exactly true or false' >&2; exit 1 ;; esac
RUN if [ "${VITE_MACHINE_CREDENTIAL_MANAGEMENT_ENABLED}" = "true" ] && { [ "${VITE_TENANT_WRITES_ENABLED}" != "true" ] || [ "${VITE_TENANT_READS_ENABLED}" != "true" ] || [ "${VITE_ACCOUNT_ACCESS_ENABLED}" != "true" ] || [ "${VITE_API_BOUNDARY_ENABLED}" != "true" ]; }; then echo 'VITE_MACHINE_CREDENTIAL_MANAGEMENT_ENABLED=true requires VITE_TENANT_WRITES_ENABLED=true, VITE_TENANT_READS_ENABLED=true, VITE_ACCOUNT_ACCESS_ENABLED=true and VITE_API_BOUNDARY_ENABLED=true' >&2; exit 1; fi
ARG VITE_POLICY_MANAGEMENT_ENABLED=false
ENV VITE_POLICY_MANAGEMENT_ENABLED=${VITE_POLICY_MANAGEMENT_ENABLED}
RUN case "${VITE_POLICY_MANAGEMENT_ENABLED}" in true|false) ;; *) echo 'VITE_POLICY_MANAGEMENT_ENABLED must be exactly true or false' >&2; exit 1 ;; esac
RUN if [ "${VITE_POLICY_MANAGEMENT_ENABLED}" = "true" ] && { [ "${VITE_ACCOUNT_ACCESS_ENABLED}" != "true" ] || [ "${VITE_API_BOUNDARY_ENABLED}" != "true" ]; }; then echo 'VITE_POLICY_MANAGEMENT_ENABLED=true requires VITE_ACCOUNT_ACCESS_ENABLED=true and VITE_API_BOUNDARY_ENABLED=true' >&2; exit 1; fi
ARG VITE_COMMERCE_SESSIONS_ENABLED=false
ENV VITE_COMMERCE_SESSIONS_ENABLED=${VITE_COMMERCE_SESSIONS_ENABLED}
RUN case "${VITE_COMMERCE_SESSIONS_ENABLED}" in true|false) ;; *) echo 'VITE_COMMERCE_SESSIONS_ENABLED must be exactly true or false' >&2; exit 1 ;; esac
RUN if [ "${VITE_COMMERCE_SESSIONS_ENABLED}" = "true" ] && { [ "${VITE_ACCOUNT_ACCESS_ENABLED}" != "true" ] || [ "${VITE_API_BOUNDARY_ENABLED}" != "true" ]; }; then echo 'VITE_COMMERCE_SESSIONS_ENABLED=true requires VITE_ACCOUNT_ACCESS_ENABLED=true and VITE_API_BOUNDARY_ENABLED=true' >&2; exit 1; fi
ARG VITE_COMMERCE_ACTIONS_ENABLED=false
ENV VITE_COMMERCE_ACTIONS_ENABLED=${VITE_COMMERCE_ACTIONS_ENABLED}
RUN case "${VITE_COMMERCE_ACTIONS_ENABLED}" in true|false) ;; *) echo 'VITE_COMMERCE_ACTIONS_ENABLED must be exactly true or false' >&2; exit 1 ;; esac
RUN if [ "${VITE_COMMERCE_ACTIONS_ENABLED}" = "true" ] && { [ "${VITE_COMMERCE_SESSIONS_ENABLED}" != "true" ] || [ "${VITE_TENANT_READS_ENABLED}" != "true" ] || [ "${VITE_ACCOUNT_ACCESS_ENABLED}" != "true" ] || [ "${VITE_API_BOUNDARY_ENABLED}" != "true" ]; }; then echo 'VITE_COMMERCE_ACTIONS_ENABLED=true requires VITE_COMMERCE_SESSIONS_ENABLED=true, VITE_TENANT_READS_ENABLED=true, VITE_ACCOUNT_ACCESS_ENABLED=true and VITE_API_BOUNDARY_ENABLED=true' >&2; exit 1; fi
ARG VITE_COMMERCE_GRANTS_ENABLED=false
ENV VITE_COMMERCE_GRANTS_ENABLED=${VITE_COMMERCE_GRANTS_ENABLED}
RUN case "${VITE_COMMERCE_GRANTS_ENABLED}" in true|false) ;; *) echo 'VITE_COMMERCE_GRANTS_ENABLED must be exactly true or false' >&2; exit 1 ;; esac
RUN if [ "${VITE_COMMERCE_GRANTS_ENABLED}" = "true" ] && { [ "${VITE_COMMERCE_ACTIONS_ENABLED}" != "true" ] || [ "${VITE_COMMERCE_SESSIONS_ENABLED}" != "true" ] || [ "${VITE_TENANT_READS_ENABLED}" != "true" ] || [ "${VITE_ACCOUNT_ACCESS_ENABLED}" != "true" ] || [ "${VITE_API_BOUNDARY_ENABLED}" != "true" ]; }; then echo 'VITE_COMMERCE_GRANTS_ENABLED=true requires VITE_COMMERCE_ACTIONS_ENABLED=true, VITE_COMMERCE_SESSIONS_ENABLED=true, VITE_TENANT_READS_ENABLED=true, VITE_ACCOUNT_ACCESS_ENABLED=true and VITE_API_BOUNDARY_ENABLED=true' >&2; exit 1; fi
ARG VITE_COMMERCE_PAYMENTS_ENABLED=false
ENV VITE_COMMERCE_PAYMENTS_ENABLED=${VITE_COMMERCE_PAYMENTS_ENABLED}
RUN case "${VITE_COMMERCE_PAYMENTS_ENABLED}" in true|false) ;; *) echo 'VITE_COMMERCE_PAYMENTS_ENABLED must be exactly true or false' >&2; exit 1 ;; esac
RUN if [ "${VITE_COMMERCE_PAYMENTS_ENABLED}" = "true" ] && { [ "${VITE_COMMERCE_GRANTS_ENABLED}" != "true" ] || [ "${VITE_COMMERCE_ACTIONS_ENABLED}" != "true" ] || [ "${VITE_COMMERCE_SESSIONS_ENABLED}" != "true" ] || [ "${VITE_TENANT_READS_ENABLED}" != "true" ] || [ "${VITE_ACCOUNT_ACCESS_ENABLED}" != "true" ] || [ "${VITE_API_BOUNDARY_ENABLED}" != "true" ]; }; then echo 'VITE_COMMERCE_PAYMENTS_ENABLED=true requires VITE_COMMERCE_GRANTS_ENABLED=true, VITE_COMMERCE_ACTIONS_ENABLED=true, VITE_COMMERCE_SESSIONS_ENABLED=true, VITE_TENANT_READS_ENABLED=true, VITE_ACCOUNT_ACCESS_ENABLED=true and VITE_API_BOUNDARY_ENABLED=true' >&2; exit 1; fi
RUN if [ "${VITE_GENERIC_AGENT_IMPORT_ENABLED}" = "true" ] && [ "${VITE_ENCRYPTED_WORKSPACE_ENABLED}" != "true" ]; then exit 1; fi
RUN if [ "${VITE_GATEWAY_EVIDENCE_ENABLED}" = "true" ] && [ "${VITE_AGENT_JOBS_ENABLED}" != "true" ]; then exit 1; fi
RUN if [ "${VITE_AGENT_JOBS_ENABLED}" = "true" ] && [ "${VITE_AGENT_REGISTRY_ENABLED}" != "true" ]; then exit 1; fi
RUN if [ "${VITE_AGENT_REGISTRY_ENABLED}" = "true" ] && [ "${VITE_ARC_OBSERVATION_ENABLED}" != "true" ]; then exit 1; fi
ARG VITE_MARKET_CATALOG_ENABLED=false
ENV VITE_MARKET_CATALOG_ENABLED=${VITE_MARKET_CATALOG_ENABLED}
RUN case "${VITE_MARKET_CATALOG_ENABLED}" in true|false) ;; *) echo 'VITE_MARKET_CATALOG_ENABLED must be exactly true or false' >&2; exit 1 ;; esac
RUN if [ "${VITE_MARKET_CATALOG_ENABLED}" = "true" ] && [ "${VITE_API_BOUNDARY_ENABLED}" != "true" ]; then echo 'VITE_MARKET_CATALOG_ENABLED=true requires VITE_API_BOUNDARY_ENABLED=true' >&2; exit 1; fi
ARG VITE_LISTING_MANAGEMENT_ENABLED=false
ENV VITE_LISTING_MANAGEMENT_ENABLED=${VITE_LISTING_MANAGEMENT_ENABLED}
RUN case "${VITE_LISTING_MANAGEMENT_ENABLED}" in true|false) ;; *) echo 'VITE_LISTING_MANAGEMENT_ENABLED must be exactly true or false' >&2; exit 1 ;; esac
RUN if [ "${VITE_LISTING_MANAGEMENT_ENABLED}" = "true" ] && { [ "${VITE_ACCOUNT_ACCESS_ENABLED}" != "true" ] || [ "${VITE_TENANT_READS_ENABLED}" != "true" ] || [ "${VITE_API_BOUNDARY_ENABLED}" != "true" ]; }; then echo 'VITE_LISTING_MANAGEMENT_ENABLED=true requires VITE_ACCOUNT_ACCESS_ENABLED=true, VITE_TENANT_READS_ENABLED=true and VITE_API_BOUNDARY_ENABLED=true' >&2; exit 1; fi
ARG VITE_MARKET_MODERATION_ENABLED=false
ENV VITE_MARKET_MODERATION_ENABLED=${VITE_MARKET_MODERATION_ENABLED}
RUN case "${VITE_MARKET_MODERATION_ENABLED}" in true|false) ;; *) echo 'VITE_MARKET_MODERATION_ENABLED must be exactly true or false' >&2; exit 1 ;; esac
RUN if [ "${VITE_MARKET_MODERATION_ENABLED}" = "true" ] && { [ "${VITE_ACCOUNT_ACCESS_ENABLED}" != "true" ] || [ "${VITE_API_BOUNDARY_ENABLED}" != "true" ]; }; then echo 'VITE_MARKET_MODERATION_ENABLED=true requires VITE_ACCOUNT_ACCESS_ENABLED=true and VITE_API_BOUNDARY_ENABLED=true' >&2; exit 1; fi
RUN pnpm --filter @openarc/shared build && pnpm --filter @openarc/web build

FROM nginx:1.29-alpine@sha256:5616878291a2eed594aee8db4dade5878cf7edcb475e59193904b198d9b830de AS runtime

RUN apk add --no-cache \
    c-ares=1.34.8-r0 \
    curl=8.22.0-r0 \
    libcrypto3=3.5.8-r0 \
    libcurl=8.22.0-r0 \
    libexpat=2.8.4-r0 \
    libssl3=3.5.8-r0 \
    libuuid=2.41.6-r1 \
    libxml2=2.13.9-r1 \
    nghttp2-libs=1.69.0-r0

ARG VITE_API_BOUNDARY_ENABLED=false
ARG VITE_ARC_OBSERVATION_ENABLED=false
ARG VITE_AGENT_REGISTRY_ENABLED=false
ARG VITE_ACCOUNT_ACCESS_ENABLED=false
ARG VITE_TENANT_READS_ENABLED=false
ARG VITE_TENANT_WRITES_ENABLED=false
ARG VITE_MACHINE_CREDENTIAL_MANAGEMENT_ENABLED=false
ARG VITE_POLICY_MANAGEMENT_ENABLED=false
ARG VITE_COMMERCE_SESSIONS_ENABLED=false
ARG VITE_COMMERCE_ACTIONS_ENABLED=false
ARG VITE_COMMERCE_GRANTS_ENABLED=false
ARG VITE_COMMERCE_PAYMENTS_ENABLED=false
ARG VITE_MARKET_CATALOG_ENABLED=false
ARG VITE_LISTING_MANAGEMENT_ENABLED=false
ARG VITE_MARKET_MODERATION_ENABLED=false
COPY apps/web/nginx.conf apps/web/nginx-api.conf apps/web/nginx-arc.conf apps/web/proxy_params apps/web/auth_proxy_params apps/web/tenant_proxy_params apps/web/tenant_write_proxy_params apps/web/commerce_agent_proxy_params apps/web/nginx-account-locations.conf apps/web/nginx-account-disabled.conf apps/web/nginx-tenant-locations.conf apps/web/nginx-tenant-write-locations.conf apps/web/nginx-tenant-disabled.conf apps/web/nginx-machine-management-locations.conf apps/web/nginx-machine-management-disabled.conf apps/web/nginx-control-capability.conf apps/web/nginx-control-deny.conf apps/web/nginx-policy-management-locations.conf apps/web/nginx-commerce-session-locations.conf apps/web/nginx-session-capability.conf apps/web/nginx-session-deny.conf apps/web/validate-m04-runtime-env.sh /tmp/openarc-nginx/
COPY apps/web/nginx-action-capability.conf apps/web/nginx-action-locations.conf apps/web/nginx-action-deny.conf /tmp/openarc-nginx/
COPY apps/web/nginx-grant-capability.conf apps/web/nginx-grant-locations.conf apps/web/nginx-grant-deny.conf /tmp/openarc-nginx/
COPY apps/web/nginx-payment-capability.conf apps/web/nginx-payment-locations.conf apps/web/nginx-payment-deny.conf /tmp/openarc-nginx/
COPY apps/web/nginx-market-capability.conf apps/web/nginx-market-catalog-locations.conf apps/web/nginx-listing-management-locations.conf apps/web/nginx-market-moderation-locations.conf apps/web/nginx-market-deny.conf apps/web/market_public_proxy_params apps/web/market_response_headers /tmp/openarc-nginx/
RUN set -eu; \
    case "${VITE_ACCOUNT_ACCESS_ENABLED}" in true|false) ;; *) echo 'VITE_ACCOUNT_ACCESS_ENABLED must be exactly true or false' >&2; exit 1 ;; esac; \
    case "${VITE_TENANT_READS_ENABLED}" in true|false) ;; *) echo 'VITE_TENANT_READS_ENABLED must be exactly true or false' >&2; exit 1 ;; esac; \
    case "${VITE_TENANT_WRITES_ENABLED}" in true|false) ;; *) echo 'VITE_TENANT_WRITES_ENABLED must be exactly true or false' >&2; exit 1 ;; esac; \
    if [ "${VITE_ACCOUNT_ACCESS_ENABLED}" = "true" ] && [ "${VITE_API_BOUNDARY_ENABLED}" != "true" ]; then echo 'VITE_ACCOUNT_ACCESS_ENABLED=true requires VITE_API_BOUNDARY_ENABLED=true' >&2; exit 1; fi; \
    if [ "${VITE_TENANT_READS_ENABLED}" = "true" ] && { [ "${VITE_ACCOUNT_ACCESS_ENABLED}" != "true" ] || [ "${VITE_API_BOUNDARY_ENABLED}" != "true" ]; }; then echo 'VITE_TENANT_READS_ENABLED=true requires VITE_ACCOUNT_ACCESS_ENABLED=true and VITE_API_BOUNDARY_ENABLED=true' >&2; exit 1; fi; \
    if [ "${VITE_TENANT_WRITES_ENABLED}" = "true" ] && { [ "${VITE_TENANT_READS_ENABLED}" != "true" ] || [ "${VITE_ACCOUNT_ACCESS_ENABLED}" != "true" ] || [ "${VITE_API_BOUNDARY_ENABLED}" != "true" ]; }; then echo 'VITE_TENANT_WRITES_ENABLED=true requires VITE_TENANT_READS_ENABLED=true, VITE_ACCOUNT_ACCESS_ENABLED=true and VITE_API_BOUNDARY_ENABLED=true' >&2; exit 1; fi; \
    case "${VITE_MACHINE_CREDENTIAL_MANAGEMENT_ENABLED}" in true|false) ;; *) echo 'VITE_MACHINE_CREDENTIAL_MANAGEMENT_ENABLED must be exactly true or false' >&2; exit 1 ;; esac; \
    if [ "${VITE_MACHINE_CREDENTIAL_MANAGEMENT_ENABLED}" = "true" ] && { [ "${VITE_TENANT_WRITES_ENABLED}" != "true" ] || [ "${VITE_TENANT_READS_ENABLED}" != "true" ] || [ "${VITE_ACCOUNT_ACCESS_ENABLED}" != "true" ] || [ "${VITE_API_BOUNDARY_ENABLED}" != "true" ]; }; then echo 'VITE_MACHINE_CREDENTIAL_MANAGEMENT_ENABLED=true requires VITE_TENANT_WRITES_ENABLED=true, VITE_TENANT_READS_ENABLED=true, VITE_ACCOUNT_ACCESS_ENABLED=true and VITE_API_BOUNDARY_ENABLED=true' >&2; exit 1; fi; \
    case "${VITE_POLICY_MANAGEMENT_ENABLED}" in true|false) ;; *) echo 'VITE_POLICY_MANAGEMENT_ENABLED must be exactly true or false' >&2; exit 1 ;; esac; \
    if [ "${VITE_POLICY_MANAGEMENT_ENABLED}" = "true" ] && { [ "${VITE_ACCOUNT_ACCESS_ENABLED}" != "true" ] || [ "${VITE_API_BOUNDARY_ENABLED}" != "true" ]; }; then echo 'VITE_POLICY_MANAGEMENT_ENABLED=true requires VITE_ACCOUNT_ACCESS_ENABLED=true and VITE_API_BOUNDARY_ENABLED=true' >&2; exit 1; fi; \
    case "${VITE_COMMERCE_SESSIONS_ENABLED}" in true|false) ;; *) echo 'VITE_COMMERCE_SESSIONS_ENABLED must be exactly true or false' >&2; exit 1 ;; esac; \
    if [ "${VITE_COMMERCE_SESSIONS_ENABLED}" = "true" ] && { [ "${VITE_ACCOUNT_ACCESS_ENABLED}" != "true" ] || [ "${VITE_API_BOUNDARY_ENABLED}" != "true" ]; }; then echo 'VITE_COMMERCE_SESSIONS_ENABLED=true requires VITE_ACCOUNT_ACCESS_ENABLED=true and VITE_API_BOUNDARY_ENABLED=true' >&2; exit 1; fi; \
    case "${VITE_COMMERCE_ACTIONS_ENABLED}" in true|false) ;; *) echo 'VITE_COMMERCE_ACTIONS_ENABLED must be exactly true or false' >&2; exit 1 ;; esac; \
    if [ "${VITE_COMMERCE_ACTIONS_ENABLED}" = "true" ] && { [ "${VITE_COMMERCE_SESSIONS_ENABLED}" != "true" ] || [ "${VITE_TENANT_READS_ENABLED}" != "true" ] || [ "${VITE_ACCOUNT_ACCESS_ENABLED}" != "true" ] || [ "${VITE_API_BOUNDARY_ENABLED}" != "true" ]; }; then echo 'VITE_COMMERCE_ACTIONS_ENABLED=true requires VITE_COMMERCE_SESSIONS_ENABLED=true, VITE_TENANT_READS_ENABLED=true, VITE_ACCOUNT_ACCESS_ENABLED=true and VITE_API_BOUNDARY_ENABLED=true' >&2; exit 1; fi; \
    case "${VITE_COMMERCE_GRANTS_ENABLED}" in true|false) ;; *) echo 'VITE_COMMERCE_GRANTS_ENABLED must be exactly true or false' >&2; exit 1 ;; esac; \
    if [ "${VITE_COMMERCE_GRANTS_ENABLED}" = "true" ] && { [ "${VITE_COMMERCE_ACTIONS_ENABLED}" != "true" ] || [ "${VITE_COMMERCE_SESSIONS_ENABLED}" != "true" ] || [ "${VITE_TENANT_READS_ENABLED}" != "true" ] || [ "${VITE_ACCOUNT_ACCESS_ENABLED}" != "true" ] || [ "${VITE_API_BOUNDARY_ENABLED}" != "true" ]; }; then echo 'VITE_COMMERCE_GRANTS_ENABLED=true requires VITE_COMMERCE_ACTIONS_ENABLED=true, VITE_COMMERCE_SESSIONS_ENABLED=true, VITE_TENANT_READS_ENABLED=true, VITE_ACCOUNT_ACCESS_ENABLED=true and VITE_API_BOUNDARY_ENABLED=true' >&2; exit 1; fi; \
    case "${VITE_COMMERCE_PAYMENTS_ENABLED}" in true|false) ;; *) echo 'VITE_COMMERCE_PAYMENTS_ENABLED must be exactly true or false' >&2; exit 1 ;; esac; \
    if [ "${VITE_COMMERCE_PAYMENTS_ENABLED}" = "true" ] && { [ "${VITE_COMMERCE_GRANTS_ENABLED}" != "true" ] || [ "${VITE_COMMERCE_ACTIONS_ENABLED}" != "true" ] || [ "${VITE_COMMERCE_SESSIONS_ENABLED}" != "true" ] || [ "${VITE_TENANT_READS_ENABLED}" != "true" ] || [ "${VITE_ACCOUNT_ACCESS_ENABLED}" != "true" ] || [ "${VITE_API_BOUNDARY_ENABLED}" != "true" ]; }; then echo 'VITE_COMMERCE_PAYMENTS_ENABLED=true requires VITE_COMMERCE_GRANTS_ENABLED=true, VITE_COMMERCE_ACTIONS_ENABLED=true, VITE_COMMERCE_SESSIONS_ENABLED=true, VITE_TENANT_READS_ENABLED=true, VITE_ACCOUNT_ACCESS_ENABLED=true and VITE_API_BOUNDARY_ENABLED=true' >&2; exit 1; fi; \
    case "${VITE_MARKET_CATALOG_ENABLED}" in true|false) ;; *) echo 'VITE_MARKET_CATALOG_ENABLED must be exactly true or false' >&2; exit 1 ;; esac; \
    if [ "${VITE_MARKET_CATALOG_ENABLED}" = "true" ] && [ "${VITE_API_BOUNDARY_ENABLED}" != "true" ]; then echo 'VITE_MARKET_CATALOG_ENABLED=true requires VITE_API_BOUNDARY_ENABLED=true' >&2; exit 1; fi; \
    case "${VITE_LISTING_MANAGEMENT_ENABLED}" in true|false) ;; *) echo 'VITE_LISTING_MANAGEMENT_ENABLED must be exactly true or false' >&2; exit 1 ;; esac; \
    if [ "${VITE_LISTING_MANAGEMENT_ENABLED}" = "true" ] && { [ "${VITE_ACCOUNT_ACCESS_ENABLED}" != "true" ] || [ "${VITE_TENANT_READS_ENABLED}" != "true" ] || [ "${VITE_API_BOUNDARY_ENABLED}" != "true" ]; }; then echo 'VITE_LISTING_MANAGEMENT_ENABLED=true requires VITE_ACCOUNT_ACCESS_ENABLED=true, VITE_TENANT_READS_ENABLED=true and VITE_API_BOUNDARY_ENABLED=true' >&2; exit 1; fi; \
    case "${VITE_MARKET_MODERATION_ENABLED}" in true|false) ;; *) echo 'VITE_MARKET_MODERATION_ENABLED must be exactly true or false' >&2; exit 1 ;; esac; \
    if [ "${VITE_MARKET_MODERATION_ENABLED}" = "true" ] && { [ "${VITE_ACCOUNT_ACCESS_ENABLED}" != "true" ] || [ "${VITE_API_BOUNDARY_ENABLED}" != "true" ]; }; then echo 'VITE_MARKET_MODERATION_ENABLED=true requires VITE_ACCOUNT_ACCESS_ENABLED=true and VITE_API_BOUNDARY_ENABLED=true' >&2; exit 1; fi; \
    if [ "${VITE_API_BOUNDARY_ENABLED}" = "true" ]; then \
      mkdir -p /etc/nginx/templates; \
      if [ "${VITE_AGENT_REGISTRY_ENABLED}" = "true" ] && [ "${VITE_ARC_OBSERVATION_ENABLED}" != "true" ]; then exit 1; fi; \
      if [ "${VITE_ARC_OBSERVATION_ENABLED}" = "true" ]; then \
        cp /tmp/openarc-nginx/nginx-arc.conf /etc/nginx/templates/default.conf.template; \
        cp /tmp/openarc-nginx/validate-m04-runtime-env.sh /docker-entrypoint.d/05-openarc-m04-env.sh; \
        chmod 755 /docker-entrypoint.d/05-openarc-m04-env.sh; \
      else \
        cp /tmp/openarc-nginx/nginx-api.conf /etc/nginx/templates/default.conf.template; \
      fi; \
      if [ "${VITE_ACCOUNT_ACCESS_ENABLED}" = "true" ]; then \
        cp /tmp/openarc-nginx/nginx-account-locations.conf /etc/nginx/templates/openarc-auth-locations.inc.template; \
        cp /tmp/openarc-nginx/auth_proxy_params /etc/nginx/auth_proxy_params; \
      else \
        cp /tmp/openarc-nginx/nginx-account-disabled.conf /etc/nginx/templates/openarc-auth-locations.inc.template; \
      fi; \
      if [ "${VITE_TENANT_READS_ENABLED}" = "true" ]; then \
        if [ "${VITE_TENANT_WRITES_ENABLED}" = "true" ]; then \
          cp /tmp/openarc-nginx/nginx-tenant-write-locations.conf /etc/nginx/templates/openarc-tenant-locations.inc.template; \
          cp /tmp/openarc-nginx/tenant_write_proxy_params /etc/nginx/tenant_write_proxy_params; \
        else \
          cp /tmp/openarc-nginx/nginx-tenant-locations.conf /etc/nginx/templates/openarc-tenant-locations.inc.template; \
        fi; \
        cp /tmp/openarc-nginx/tenant_proxy_params /etc/nginx/tenant_proxy_params; \
      else \
        cp /tmp/openarc-nginx/nginx-tenant-disabled.conf /etc/nginx/templates/openarc-tenant-locations.inc.template; \
      fi; \
      if [ "${VITE_LISTING_MANAGEMENT_ENABLED}" = "true" ] || [ "${VITE_MARKET_MODERATION_ENABLED}" = "true" ]; then \
        cp /tmp/openarc-nginx/tenant_proxy_params /etc/nginx/tenant_proxy_params; \
        cp /tmp/openarc-nginx/tenant_write_proxy_params /etc/nginx/tenant_write_proxy_params; \
      fi; \
      if [ "${VITE_MACHINE_CREDENTIAL_MANAGEMENT_ENABLED}" = "true" ]; then \
        cp /tmp/openarc-nginx/nginx-machine-management-locations.conf /etc/nginx/templates/openarc-machine-locations.inc.template; \
      else \
        cp /tmp/openarc-nginx/nginx-machine-management-disabled.conf /etc/nginx/templates/openarc-machine-locations.inc.template; \
      fi; \
      cp /tmp/openarc-nginx/nginx-control-capability.conf /etc/nginx/templates/openarc-control-capability-locations.inc.template; \
      cp /tmp/openarc-nginx/nginx-control-deny.conf /etc/nginx/templates/openarc-control-deny.inc.template; \
      cp /tmp/openarc-nginx/nginx-session-capability.conf /etc/nginx/templates/openarc-session-capability-locations.inc.template; \
      cp /tmp/openarc-nginx/nginx-session-deny.conf /etc/nginx/templates/openarc-session-deny.inc.template; \
      if [ "${VITE_POLICY_MANAGEMENT_ENABLED}" = "true" ]; then \
        cp /tmp/openarc-nginx/nginx-policy-management-locations.conf /etc/nginx/templates/openarc-policy-management-locations.inc.template; \
        cp /tmp/openarc-nginx/tenant_proxy_params /etc/nginx/tenant_proxy_params; \
        cp /tmp/openarc-nginx/tenant_write_proxy_params /etc/nginx/tenant_write_proxy_params; \
      else \
        : > /etc/nginx/templates/openarc-policy-management-locations.inc.template; \
      fi; \
      if [ "${VITE_COMMERCE_SESSIONS_ENABLED}" = "true" ]; then \
        cp /tmp/openarc-nginx/nginx-commerce-session-locations.conf /etc/nginx/templates/openarc-commerce-session-locations.inc.template; \
        cp /tmp/openarc-nginx/tenant_proxy_params /etc/nginx/tenant_proxy_params; \
        cp /tmp/openarc-nginx/tenant_write_proxy_params /etc/nginx/tenant_write_proxy_params; \
        cp /tmp/openarc-nginx/commerce_agent_proxy_params /etc/nginx/commerce_agent_proxy_params; \
      else \
        : > /etc/nginx/templates/openarc-commerce-session-locations.inc.template; \
      fi; \
      cp /tmp/openarc-nginx/nginx-action-capability.conf /etc/nginx/templates/openarc-action-capability-locations.inc.template; \
      cp /tmp/openarc-nginx/nginx-action-deny.conf /etc/nginx/templates/openarc-action-deny.inc.template; \
      if [ "${VITE_COMMERCE_ACTIONS_ENABLED}" = "true" ]; then \
        cp /tmp/openarc-nginx/nginx-action-locations.conf /etc/nginx/templates/openarc-commerce-action-locations.inc.template; \
        cp /tmp/openarc-nginx/tenant_proxy_params /etc/nginx/tenant_proxy_params; \
        cp /tmp/openarc-nginx/tenant_write_proxy_params /etc/nginx/tenant_write_proxy_params; \
        cp /tmp/openarc-nginx/commerce_agent_proxy_params /etc/nginx/commerce_agent_proxy_params; \
      else \
        : > /etc/nginx/templates/openarc-commerce-action-locations.inc.template; \
      fi; \
      cp /tmp/openarc-nginx/nginx-grant-capability.conf /etc/nginx/templates/openarc-grant-capability-locations.inc.template; \
      cp /tmp/openarc-nginx/nginx-grant-deny.conf /etc/nginx/templates/openarc-grant-deny.inc.template; \
      if [ "${VITE_COMMERCE_GRANTS_ENABLED}" = "true" ]; then \
        cp /tmp/openarc-nginx/nginx-grant-locations.conf /etc/nginx/templates/openarc-commerce-grant-locations.inc.template; \
        cp /tmp/openarc-nginx/tenant_proxy_params /etc/nginx/tenant_proxy_params; \
        cp /tmp/openarc-nginx/tenant_write_proxy_params /etc/nginx/tenant_write_proxy_params; \
        cp /tmp/openarc-nginx/commerce_agent_proxy_params /etc/nginx/commerce_agent_proxy_params; \
      else \
        : > /etc/nginx/templates/openarc-commerce-grant-locations.inc.template; \
      fi; \
      cp /tmp/openarc-nginx/nginx-payment-capability.conf /etc/nginx/templates/openarc-payment-capability-locations.inc.template; \
      cp /tmp/openarc-nginx/nginx-payment-deny.conf /etc/nginx/templates/openarc-payment-deny.inc.template; \
      if [ "${VITE_COMMERCE_PAYMENTS_ENABLED}" = "true" ]; then \
        cp /tmp/openarc-nginx/nginx-payment-locations.conf /etc/nginx/templates/openarc-commerce-payment-locations.inc.template; \
        cp /tmp/openarc-nginx/tenant_write_proxy_params /etc/nginx/tenant_write_proxy_params; \
        cp /tmp/openarc-nginx/commerce_agent_proxy_params /etc/nginx/commerce_agent_proxy_params; \
      else \
        : > /etc/nginx/templates/openarc-commerce-payment-locations.inc.template; \
      fi; \
      cp /tmp/openarc-nginx/nginx-market-capability.conf /etc/nginx/templates/openarc-market-capability-locations.inc.template; \
      cp /tmp/openarc-nginx/nginx-market-deny.conf /etc/nginx/templates/openarc-market-deny.inc.template; \
      cp /tmp/openarc-nginx/market_public_proxy_params /etc/nginx/market_public_proxy_params; \
      cp /tmp/openarc-nginx/market_response_headers /etc/nginx/market_response_headers; \
      if [ "${VITE_MARKET_CATALOG_ENABLED}" = "true" ]; then \
        cp /tmp/openarc-nginx/nginx-market-catalog-locations.conf /etc/nginx/templates/openarc-market-catalog-locations.inc.template; \
      else \
        : > /etc/nginx/templates/openarc-market-catalog-locations.inc.template; \
      fi; \
      if [ "${VITE_LISTING_MANAGEMENT_ENABLED}" = "true" ]; then \
        cp /tmp/openarc-nginx/nginx-listing-management-locations.conf /etc/nginx/templates/openarc-listing-management-locations.inc.template; \
      else \
        : > /etc/nginx/templates/openarc-listing-management-locations.inc.template; \
      fi; \
      if [ "${VITE_MARKET_MODERATION_ENABLED}" = "true" ]; then \
        cp /tmp/openarc-nginx/nginx-market-moderation-locations.conf /etc/nginx/templates/openarc-market-moderation-locations.inc.template; \
      else \
        : > /etc/nginx/templates/openarc-market-moderation-locations.inc.template; \
      fi; \
      cp /tmp/openarc-nginx/proxy_params /etc/nginx/proxy_params; \
      rm -f /etc/nginx/conf.d/default.conf; \
    else \
      cp /tmp/openarc-nginx/nginx.conf /etc/nginx/conf.d/default.conf; \
    fi; \
    rm -rf /tmp/openarc-nginx
ENV API_TRUST_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    NGINX_ENVSUBST_FILTER=^(API_(UPSTREAM_(HOST|SNI)|TRUST_BUNDLE)|SOURCE_PROXY_SECRET)$
COPY --from=build /app/apps/web/dist /usr/share/nginx/html

EXPOSE 8080
