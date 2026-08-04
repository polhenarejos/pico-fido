@echo off
setlocal EnableExtensions
call "%~dp0docker_env.bat" || exit /b 1
if not defined LEGACY_SOURCE_DIR set "LEGACY_SOURCE_DIR=%REPO_ROOT%\legacy"
if not exist "%LEGACY_SOURCE_DIR%\CMakeLists.txt" (
    echo Legacy checkout not found: %LEGACY_SOURCE_DIR% 1>&2
    exit /b 1
)
docker.exe container run --rm --cap-add ALL --privileged --volume "%LEGACY_SOURCE_DIR%:/legacy" --workdir /legacy "%DOCKER_IMAGE_TAG%" bash -eu -c "mkdir -p build_in_docker && cd build_in_docker && cmake -DENABLE_EMULATION=1 -DENABLE_EDDSA=1 .. && make -j %NUMBER_OF_PROCESSORS%"
exit /b %ERRORLEVEL%
