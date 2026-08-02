@echo off
setlocal EnableExtensions
call "%~dp0docker_env.bat" || exit /b 1
docker.exe container run --rm --cap-add ALL --privileged --volume "%REPO_ROOT%:/workspace" --workdir /workspace "%DOCKER_IMAGE_TAG%" bash -eu -c "mkdir -p build_in_docker && cd build_in_docker && cmake -DENABLE_EMULATION=1 -DENABLE_EDDSA=1 .. && make -j %NUMBER_OF_PROCESSORS%"
exit /b %ERRORLEVEL%
