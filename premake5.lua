workspace "cryptopals"
    configurations { "Debug", "Release" }
    platforms { "x64" }

function base(name)
    project(name)
        kind "ConsoleApp"
        language "C"
        cdialect "C11"
        buildoptions { "/Zc:preprocessor", "/volatile:iso", "/std:c11", "/TC", "/EHc" }
        targetdir "bin/%{cfg.buildcfg}"

        files{ name .. ".c", "utils.h", "utils.c" }

        filter { "configurations:Debug" }
            defines { "DEBUG" }
            symbols "On"
            targetsuffix "_d"

        filter { "configurations:Release" }
            defines { "NDEBUG" }
            optimize "On"

        filter { "system:windows" }
            platforms { "x64" }

        filter { "system:windows", "configurations:Release" }
            flags { "NoIncrementalLink" }

        filter { "system:linux" }
            platforms { "linux64" }
            links { "pthread", "dl" }
end


newaction {
   trigger     = "clean",
   description = "clean the build",
   execute     = function ()
       print("clean the build...")
       os.rmdir("./.vs")
       os.rmdir("./bin")
       os.rmdir("./obj")
       os.remove("./*.vcxproj*")
       os.remove("./*.sln")
       print("done.")
   end
}

base("set1ch1")
base("set1ch2")
base("set1ch3")
base("set1ch4")
base("set1ch5")
base("set1ch6")
base("set1ch7")
    links { "tomcrypt", "tommath" }
base("set1ch8")
   links { "tomcrypt", "tommath" }