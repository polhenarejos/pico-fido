@echo off
setlocal EnableExtensions
call "%~dp0docker_env.bat" || exit /b 1
docker.exe container run --rm --cap-add ALL --privileged --volume "%REPO_ROOT%:/workspace" --workdir /workspace -e PICO_FIDO_COMPAT_CONTAINER=1 -e LEGACY_FIDO_EMULATOR=/workspace/legacy/build_in_docker/pico_fido -e CURRENT_FIDO_EMULATOR=/workspace/build_in_docker/pico_fido "%DOCKER_IMAGE_TAG%" bash -eu ./tests/run-test-041-in-docker.sh
exit /b %ERRORLEVEL%
