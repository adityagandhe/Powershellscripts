$adminSiteUrl = "https://yavatmal3-admin.sharepoint.com"
$themeName = "Multicolored green updated theme"
Connect-SPOService $adminSiteUrl
#Replace the variable value with the generated code
$palette = @{
    "themePrimary" = "#006b35"; #Navy
    "themeLighterAlt" = "#ed2985";
    "themeLighter" = "#c2e7d5"; #Coral, themeLighter
    "themeLight" = "#93d3b3"; #Coral, themeLight
    "themeTertiary" = "#43a674";
    "themeSecondary" = "#0f7d46";
    "themeDarkAlt" = "#006030"; #Coral;
    "themeDark" = "#005129"; #Coral
    "themeDarker" = "#003c1e";
    "neutralLighterAlt" = "#eff9f4";
    "neutralLighter" = "#85bf71";
    "neutralLight" = "#eaeaea";
    "neutralQuaternaryAlt" = "#dadada";
    "neutralQuaternary" = "#d0d0d0";
    "neutralTertiaryAlt" = "#c8c8c8";
    "neutralTertiary" = "#595959";
    "neutralSecondary" = "#53C7BD"; #Turquoise
    "neutralPrimaryAlt" = "#2f2f2f";
    "neutralPrimary" = "#452667";
    "neutralDark" = "#151515";
    "black" = "#3f3f3f";
    "white" = "#ffffff";
    "accent" = "#F87060"; #Coral;
    "backgroundOverlay" = "#006b35"; #Navy
}

https://support-public.cfm.quest.com/52314_MetalogixContentMatrix_8.9_SharePointEdition.pdf
Add-SPOTheme -Name $themeName -Palette $palette -IsInverted:$false -Overwrite