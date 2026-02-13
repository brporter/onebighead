# Runtime-only Dockerfile
# Build the application first using: ./build/build.sh --clean -o publish
# Then build the image: docker build -t onebighead .

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY publish/ .
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080
ENTRYPOINT ["dotnet", "backend.dll"]
