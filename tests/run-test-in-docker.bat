@echo off
setlocal EnableExtensions
call "%~dp0docker_env.bat" || exit /b 1
docker.exe container run --rm --cap-add ALL --privileged --volume "%REPO_ROOT%:/workspace" --workdir /workspace "%DOCKER_IMAGE_TAG%" bash -eu ./tests/start-up-and-test.sh
exit /b %ERRORLEVEL%
