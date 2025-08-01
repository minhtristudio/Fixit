    -- AUTOSAVE PATCH START
    pcall(function()
        local HttpService = game:GetService("HttpService")
        if typeof(readfile) == "function" and typeof(isfile) == "function" and isfile("RoClothesSettings.json") then
            local saved = HttpService:JSONDecode(readfile("RoClothesSettings.json"))
            -- Restore booleans
            if typeof(saved.ToggleBBC) == "boolean" then
                PlayerData[SelectPlayer].ToggleBBC = saved.ToggleBBC
            end
            if typeof(saved.TearParticles) == "boolean" then
                PlayerData[SelectPlayer].TearParticles = saved.TearParticles
            end
            if typeof(saved.HealParticles) == "boolean" then
                PlayerData[SelectPlayer].HealParticles = saved.HealParticles
            end
            -- Restore Catalog Username
            if typeof(saved.CatalogUsername) == "string" then
                PlayerData[SelectPlayer].CatalogUsername = saved.CatalogUsername
                if GUIObject and GUIObject.UsernameTextbox then
                    GUIObject.UsernameTextbox.Text = saved.CatalogUsername
                end
            end
            -- Restore Method value
            if typeof(saved.Method) == "number" then
                Method = saved.Method
                if GUIObject and GUIObject.MethodButton then
                    GUIObject.MethodButton.Text = "Method: " .. Method
                end
            end
            Function.GUIUpdate()
        end
    end)

    task.spawn(function()
        local HttpService = game:GetService("HttpService")
        while task.wait(3) do
            pcall(function()
                if typeof(writefile) == "function" then
                    writefile("RoClothesSettings.json", HttpService:JSONEncode({
                        ToggleBBC = PlayerData[SelectPlayer].ToggleBBC,
                        TearParticles = PlayerData[SelectPlayer].TearParticles,
                        HealParticles = PlayerData[SelectPlayer].HealParticles,
                        CatalogUsername = PlayerData[SelectPlayer].CatalogUsername,
                        Method = Method,
                    }))
                end
            end)
        end
    end)
    -- AUTOSAVE PATCH END
