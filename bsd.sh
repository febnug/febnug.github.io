#!/bin/sh

set -e

# === 1. Persiapan ===
KERNEL_NAME="FEBRI"
SRC_DIR="/usr/src"
OBJ_DIR="/usr/obj/usr/src/amd64.amd64/sys/${KERNEL_NAME}"
BASE_DIR="/tmp/base"
MFSBSD_DIR="/tmp/mfsbsd"
FREEBSD_VER="14.0-RELEASE"
BASE_URL="https://download.freebsd.org/ftp/releases/amd64/${FREEBSD_VER}/base.txz"

echo "[*] Membuat kernel config '${KERNEL_NAME}'..."
mkdir -p ${SRC_DIR}/sys/amd64/conf
cp ${SRC_DIR}/sys/amd64/conf/GENERIC ${SRC_DIR}/sys/amd64/conf/${KERNEL_NAME}
sed -i '' "s/^ident.*/ident\t\t${KERNEL_NAME}/" ${SRC_DIR}/sys/amd64/conf/${KERNEL_NAME}

echo "[*] Build kernel '${KERNEL_NAME}'..."
cd ${SRC_DIR}
make buildkernel KERNCONF=${KERNEL_NAME}

# === 2. Siapkan base.txz ===
echo "[*] Download base.txz ${FREEBSD_VER}..."
mkdir -p "${BASE_DIR}"
fetch -o /tmp/base.txz "${BASE_URL}"
tar -xf /tmp/base.txz -C "${BASE_DIR}"

# === 3. Clone mfsbsd ===
echo "[*] Clone mfsbsd..."
rm -rf "${MFSBSD_DIR}"
git clone https://github.com/mmatuska/mfsbsd.git "${MFSBSD_DIR}"

# === 4. Salin kernel hasil build ===
echo "[*] Ganti kernel mfsbsd dengan '${KERNEL_NAME}'..."
cp "${OBJ_DIR}/kernel" "${MFSBSD_DIR}/root/boot/kernel/kernel"

# === 5. Set BASE environment dan build ISO ===
echo "[*] Build ISO mfsbsd..."
cd "${MFSBSD_DIR}"
export BASE="${BASE_DIR}"
make iso

echo "[✓] ISO berhasil dibuat di: ${MFSBSD_DIR}/mfsbsd-${FREEBSD_VER}-amd64.iso"
