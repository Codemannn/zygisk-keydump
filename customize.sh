#!/system/bin/sh
# Zygisk module: SSL Key Dump
# Target: com.yzj.kaipanh
MODDIR=${0%/*}
TARGET_PKG="com.yzj.kaipanh"

# Set target package for the hook
echo "$TARGET_PKG" > "$MODDIR/target.txt"
