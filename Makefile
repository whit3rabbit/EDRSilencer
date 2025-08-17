all:
    @msbuild.exe EDRSilencer-BOF.sln /p:Configuration=Release /p:Platform=x64

all-debug:
    @msbuild.exe EDRSilencer-BOF.sln /p:Configuration=Debug /p:Platform=x64

clean:
    @msbuild.exe EDRSilencer-BOF.sln /t:Clean