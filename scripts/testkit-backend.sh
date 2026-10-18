#!/usr/bin/env bash
# CR-15: a live dur.io backend for the testkit, in Docker, from the stoatchat
# checkout next to this repo (workspace layout; STOATCHAT_DIR to override).
#
#   scripts/testkit-backend.sh up      # infra (mongo rs0, redis, rabbitmq, MinIO) + debug builds of
#                                      # delta, bonfire, autumn, each in its own container on durio-test
#   scripts/testkit-backend.sh test    # the testkit against it (JUnit XML: out/testkit/junit.xml)
#   scripts/testkit-backend.sh check   # Mongo/MinIO hold ciphertext only (evidence from the last test run)
#   scripts/testkit-backend.sh down    # stop the services and MinIO (infra: tools/rust-dev/test-env.sh down)
#
# Config only through REVOLT__* env vars: E2EE on, open registration without
# e-mail verification or captcha. Rate limits stay on (the testkit backs off on 429).
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)
WORKSPACE=$(cd .. && pwd)
STOATCHAT_DIR=${STOATCHAT_DIR:-$WORKSPACE/stoatchat}
TEST_ENV=${TEST_ENV:-$WORKSPACE/tools/rust-dev/test-env.sh}
NET=durio-test
IMAGE=durio-rust-dev:local
MINIO_IMAGE=pgsty/silo:RELEASE.2026-09-16T00-00-00Z
MC_IMAGE=pgsty/mc:RELEASE.2026-09-16T00-00-00Z
S3_USER=minioautumn
S3_PASS=minioautumn
SERVICES="delta bonfire autumn"
winpath() { (cd "$1" && (pwd -W 2>/dev/null || pwd)); }

revolt_env() {
    cat <<EOF
REVOLT__DATABASE__MONGODB=mongodb://durio-test-mongo/?replicaSet=rs0
REVOLT__DATABASE__REDIS=redis://durio-test-redis/
REVOLT__RABBIT__HOST=durio-test-rabbit
REVOLT__HOSTS__APP=http://durio-test-delta:14702
REVOLT__HOSTS__API=http://durio-test-delta:14702
REVOLT__HOSTS__EVENTS=ws://durio-test-bonfire:14703
REVOLT__HOSTS__AUTUMN=http://durio-test-autumn:14704
REVOLT__HOSTS__JANUARY=http://durio-test-january:14705
REVOLT__FEATURES__E2EE__ENABLED=true
REVOLT__API__REGISTRATION__INVITE_ONLY=false
REVOLT__API__SMTP__HOST=
REVOLT__API__SECURITY__CAPTCHA__HCAPTCHA_KEY=
REVOLT__FEATURES__LIMITS__NEW_USER__OUTGOING_FRIEND_REQUESTS=100
# q11_full_mailbox_retry fills a mailbox; other scenarios stay far below
REVOLT__FEATURES__E2EE__MAX_PENDING_TO_DEVICE=64
REVOLT__FILES__S3__ENDPOINT=http://durio-test-minio:9000
REVOLT__FILES__S3__PATH_STYLE_BUCKETS=true
REVOLT__FILES__S3__REGION=minio
REVOLT__FILES__S3__ACCESS_KEY_ID=$S3_USER
REVOLT__FILES__S3__SECRET_ACCESS_KEY=$S3_PASS
REVOLT__FILES__S3__DEFAULT_BUCKET=revolt-uploads
RUST_LOG=warn
EOF
}

up() {
    docker container inspect durio-test-mongo >/dev/null 2>&1 || sh "$TEST_ENV" up
    echo "building revolt-delta, revolt-bonfire, revolt-autumn (debug)"
    MSYS_NO_PATHCONV=1 docker run --rm -v "$(winpath "$STOATCHAT_DIR"):/src" \
        -v durio-cargo-target:/target -v durio-cargo-registry:/usr/local/cargo/registry \
        -w /src -e CARGO_TARGET_DIR=/target -e CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-6}" \
        $IMAGE cargo build -q -p revolt-delta -p revolt-bonfire -p revolt-autumn

    if ! docker container inspect durio-test-minio >/dev/null 2>&1; then
        docker run -d --rm --name durio-test-minio --network $NET \
            -e MINIO_ROOT_USER=$S3_USER -e MINIO_ROOT_PASSWORD=$S3_PASS $MINIO_IMAGE server /data >/dev/null
    fi
    i=0
    until MSYS_NO_PATHCONV=1 docker run --rm --network $NET -e MC_HOST_m=http://$S3_USER:$S3_PASS@durio-test-minio:9000 \
        $MC_IMAGE mb --ignore-existing m/revolt-uploads >/dev/null 2>&1; do
        i=$((i + 1)); [ $i -lt 30 ] || { echo "minio did not start" >&2; exit 1; }
        sleep 1
    done

    mkdir -p out && env_file=out/testkit-backend.env  # docker.exe cannot read Git Bash /tmp
    revolt_env > "$env_file"
    for s in $SERVICES; do
        docker rm -f durio-test-$s >/dev/null 2>&1 || true
        MSYS_NO_PATHCONV=1 docker run -d --rm --name durio-test-$s --network $NET --env-file "$env_file" \
            -v durio-cargo-target:/target:ro -w / $IMAGE /target/debug/revolt-$s >/dev/null
    done
    rm -f "$env_file"
    i=0
    until docker run --rm --network $NET alpine:3.22 wget -qO- http://durio-test-delta:14702/ 2>/dev/null | grep -q '"e2ee"'; do
        i=$((i + 1)); [ $i -lt 120 ] || { docker logs durio-test-delta | tail -20 >&2; exit 1; }
        sleep 1
    done
    for s in bonfire autumn; do
        docker container inspect durio-test-$s >/dev/null 2>&1 || { echo "$s exited" >&2; exit 1; }
    done
    echo "backend up: http://durio-test-delta:14702 ws://durio-test-bonfire:14703 http://durio-test-autumn:14704 (network $NET)"
}

run_test() {
    mkdir -p out/testkit
    DCARGO_DOCKER_ARGS="--network $NET -e STOAT_API=http://durio-test-delta:14702 -e STOAT_WS=ws://durio-test-bonfire:14703 -e STOAT_AUTUMN=http://durio-test-autumn:14704 -e STOAT_TESTKIT_OUT=/work/out/testkit" \
        scripts/dcargo.sh sh -c 'command -v cargo-nextest >/dev/null || curl -LsSf https://get.nexte.st/0.9/linux | tar zxf - -C /tools/bin;
            cargo nextest run --locked -p stoat-crypto-testkit --profile testkit --run-ignored only; rc=$?;
            cp target/nextest/testkit/junit.xml out/testkit/ 2>/dev/null; exit $rc'
}

check() {
    dir=out/testkit/evidence
    ls "$dir"/*.json >/dev/null 2>&1 || { echo "no $dir/*.json: run the tests first" >&2; exit 1; }
    merged=out/testkit/evidence-all.json
    { printf '['; sep=; for f in "$dir"/*.json; do printf '%s' "$sep"; cat "$f"; sep=,; done; printf ']'; } > "$merged"
    docker cp "$merged" durio-test-mongo:/tmp/evidence.json
    rm -f "$merged"
    out=$(docker exec durio-test-mongo mongosh --quiet revolt --eval '
        const runs = JSON.parse(require("fs").readFileSync("/tmp/evidence.json", "utf8"));
        let bad = 0, channels = 0, files = 0;
        for (const ev of runs) {
            for (const m of ev.messages) {
                channels++;
                const docs = db.messages.find({ channel: m.channel, encrypted: { $exists: true } }).toArray();
                if (docs.length === 0) { print("BAD no encrypted messages in " + m.channel); bad++; }
                for (const d of docs) {
                    if (d.content) { print("BAD content stored for " + d._id); bad++; }
                    if (JSON.stringify(d).includes(m.marker)) { print("BAD plaintext in " + d._id); bad++; }
                }
            }
            for (const f of ev.files) {
                files++;
                print("PLAIN " + f.plaintext_sha256);
                const a = db.attachments.findOne({ _id: f.id });
                if (!a || a.encrypted !== true) { print("BAD file " + f.id + " not stored as encrypted"); bad++; continue; }
                if (a.hash === f.plaintext_sha256) { print("BAD file " + f.id + " is the plaintext"); bad++; }
            }
        }
        print(`mongo: ${channels} channels, ${files} files, ${bad === 0 ? "ciphertext only" : bad + " problems"}`);')
    echo "$out" | grep -v '^PLAIN '
    fail=0
    echo "$out" | grep -q '^BAD' && fail=1
    # autumn names objects by the SHA-256 of the upload: none may carry a plaintext hash
    for h in $(echo "$out" | sed -n 's/^PLAIN //p'); do
        if MSYS_NO_PATHCONV=1 docker run --rm --network $NET -e MC_HOST_m=http://$S3_USER:$S3_PASS@durio-test-minio:9000 \
            $MC_IMAGE stat "m/revolt-uploads/$h" >/dev/null 2>&1; then
            echo "BAD MinIO holds an object named by a plaintext hash: $h"
            fail=1
        fi
    done
    [ $fail = 0 ] && echo "minio: no plaintext objects"
    return $fail
}

down() {
    for s in $SERVICES minio; do docker rm -f durio-test-$s >/dev/null 2>&1 || true; done
    echo "testkit backend down (infra: $TEST_ENV down)"
}

case ${1:-} in
up) up ;;
test) run_test ;;
check) check ;;
down) down ;;
*) sed -n '2,12p' "$0"; exit 2 ;;
esac
