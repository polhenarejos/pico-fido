@echo off

if not defined MBEDTLS_DOCKER_GUEST set "MBEDTLS_DOCKER_GUEST=bookworm"
set "DOCKER_IMAGE_TAG=pico-hsm-test:%MBEDTLS_DOCKER_GUEST%"

where docker.exe >nul 2>&1 || (
    echo Docker is required but is not installed or is not on PATH. 1>&2
    exit /b 1
)

for %%I in ("%~dp0..") do set "REPO_ROOT=%%~fI"

echo Getting Docker image up to date ^(this may take a few minutes^)...
docker.exe image build -t "%DOCKER_IMAGE_TAG%" --cache-from="%DOCKER_IMAGE_TAG%" --build-arg "MAKEFLAGS_PARALLEL=-j %NUMBER_OF_PROCESSORS%" "%REPO_ROOT%\tests\docker\%MBEDTLS_DOCKER_GUEST%"
exit /b %ERRORLEVEL%
