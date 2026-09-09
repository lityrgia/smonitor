#!/usr/bin/env zsh

setopt errexit nounset pipefail

config=${1:-Debug}
if [[ $config != Debug && $config != Release ]]; then
    print -u2 "usage: ${0:t} [Debug|Release]"
    exit 2
fi

root=${0:A:h}
project=$root/etw_hook
obj_dir=$root/objs/x64/$config
out_dir=$root/outputs/x64/$config
msvc=/home/nixtar/msvc/bin/x64
wdk_crt='/home/nixtar/msvc/Windows Kits/10/Include/10.0.26100.0/km/crt'

mkdir -p "$obj_dir" "$out_dir"

compile_flags=(
    /c /nologo /W4 /WX- /wd4324 /diagnostics:column
    /GF /Zp8 /GS /Gy /fp:precise /Qspectre
    /Zc:wchar_t- /Zc:forScope /Zc:inline /GR- /std:c++17
    /Gz /external:W4 /utf-8 /kernel
    /D_WIN64 /D_AMD64_ /DAMD64 /DDEPRECATE_DDK_FUNCTIONS=1
    /D_WIN32_WINNT=0x0A00 /DWINVER=0x0A00 /DWINNT=1
    /DNTDDI_VERSION=0x0A000010
    "/I$wdk_crt" "/I$project/include" "/I$root/../shared" /FIwarning.h
    "/Fo$obj_dir/"
)

if [[ $config == Release ]]; then
    compile_flags+=(/O2 /Oi)
else
    compile_flags+=(/Od /Oi /Oy- /Z7 /DDBG=1)
fi

sources=(
    "$project/src/etwhook_init.cpp"
    "$project/src/etwhook_main.cpp"
    "$project/src/etwhook_manager.cpp"
    "$project/src/etwhook_utils.cpp"
)

"$msvc/cl" "${compile_flags[@]}" "${sources[@]}"

objects=(
    "$obj_dir/etwhook_init.obj"
    "$obj_dir/etwhook_main.obj"
    "$obj_dir/etwhook_manager.obj"
    "$obj_dir/etwhook_utils.obj"
)

link_flags=(
    /nologo "/out:$out_dir/swatcher.sys" /version:10.0
    /incremental:no /wx /section:INIT,d /nodefaultlib /manifest:no
    /subsystem:native,10.00 /driver /opt:ref /opt:icf
    /entry:GsDriverEntry /release /merge:_TEXT=.text /merge:_PAGE=PAGE
    /machine:x64 /kernel /osversion:10.0
    /ignore:4198,4010,4037,4039,4065,4070,4078,4087,4089,4221,4108,4088,4218,4235
)

if [[ $config == Debug ]]; then
    link_flags+=(/debug "/pdb:$out_dir/etw_hook.pdb")
fi

"$msvc/link" "${link_flags[@]}" "${objects[@]}" \
    BufferOverflowFastFailK.lib ntoskrnl.lib hal.lib wmilib.lib libcntpr.lib

print "built: $out_dir/swatcher.sys"
