using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using GatewayOnPrem.Extensions;
using GatewayOnPrem.ViewModels;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace GatewayOnPrem.Models
{
    public class OSRLogin
    {
        private ILogger<OSRLogin> Logger;
        const string tenantLogin = "/api/dw/gateway/tenantLogin";
        #region Private Properties
        private SolverEnvironment EnvironmentName { get; }
        private string Username { get; }
        private string Password { get; }
        private string TenantName { get; }
        private string CustomUrl { get; }
        #endregion Private Properties

        public OSRLogin(OSRViewModel input)
        {
            EnvironmentName = input.EnvironmentName;
            Username = input.Username;
            Password = input.Password;
            CustomUrl = input.CustomUrl;
            Logger = ApplicationLogging.CreateLogger<OSRLogin>();
        }
        public async Task<TenantUserInfo> GetTenantUserInfo()
        {
            var h = new HttpClientHandler
            {
                AllowAutoRedirect = true,
                UseCookies = true,
                CookieContainer = new CookieContainer(),
                AutomaticDecompression = DecompressionMethods.GZip
            };
            using (var c = new HttpClient(h))
            {
                c.DefaultRequestHeaders.Add("Accept-Encoding", "gzip");

                var portalUrl = new UriBuilder(EnvironmentName == SolverEnvironment.Custom
                    ? CustomUrl
                    : EnvironmentName.GetAttributeDescription())
                {
                    Scheme = Uri.UriSchemeHttps,
                    Port = 443,
                }.Uri;

                if (string.IsNullOrWhiteSpace(portalUrl.ToString()))
                {
                    throw new InvalidOperationException($"Invalid portal URL {portalUrl}");
                }
                this.Logger.LogInformation($"Cookie being passed from {portalUrl}:{h.CookieContainer.GetCookies(portalUrl)}");
                using (var loginResult = await c.PostAsync(portalUrl + "/api/osr-authentication/login",
                    new StringContent(JsonConvert.SerializeObject(new { Username, Password }), Encoding.UTF8, "application/json")).ConfigureAwait(false))
                {
                    this.Logger.LogInformation($"Cookie being passed from {portalUrl + "/api/osr-authentication/login"}:{h.CookieContainer.GetCookies(new Uri(portalUrl + "/api/osr-authentication/login"))}");
                    if (loginResult.IsSuccessStatusCode)
                    {
                        using (var currentTenantId = await c.GetAsync(portalUrl + "/api/dw").ConfigureAwait(false))
                        {
                            var serializer = new JsonSerializer();
                            var tenantJsonArray = JsonConvert.DeserializeObject<JArray>(await currentTenantId.Content.ReadAsStringAsync().ConfigureAwait(false));
                            Dictionary<string, string> dict = tenantJsonArray.ToDictionary(k => ((JObject)k).Properties().First().Name, v => v.Values().First().Value<string>());
                            var maybeTenantUsers = await c.GetAsync(portalUrl + "api/portal/user").ConfigureAwait(false);
                            return serializer.Deserialize<TenantUserInfo>
                                (new JsonTextReader(new StreamReader(await maybeTenantUsers.Content.ReadAsStreamAsync().ConfigureAwait(false))));
                        }
                    }
                    else
                    {
                        throw new Exception($"Error {loginResult.StatusCode}, {await loginResult.Content.ReadAsStringAsync()}.");
                    }
                }
            }
        }

        public async Task<GatewayConnectionInfo> AuthorizeLogin(Tenant tenantInfo, Guid? tenantId)
        {
            var h = new HttpClientHandler
            {
                AllowAutoRedirect = true,
                UseCookies = true,
                CookieContainer = new CookieContainer(),
                AutomaticDecompression = DecompressionMethods.GZip
            };
            using (var c = new HttpClient(h))
            {
                c.DefaultRequestHeaders.Add("Accept-Encoding", "gzip");

                var portalUrl = new UriBuilder(EnvironmentName == SolverEnvironment.Custom
                    ? CustomUrl
                    : EnvironmentName.GetAttributeDescription())
                {
                    Scheme = Uri.UriSchemeHttps,
                    Port = 443,
                }.Uri;

                if (string.IsNullOrWhiteSpace(portalUrl.ToString()))
                {
                    throw new InvalidOperationException($"Invalid portal URL {portalUrl}");
                }
                this.Logger.LogInformation($"Cookie being passed from {portalUrl}:{h.CookieContainer.GetCookies(portalUrl)}");
                using (var loginResult = await c.PostAsync(portalUrl + "/api/osr-authentication/login",
                    new StringContent(JsonConvert.SerializeObject(new { Username, Password }), Encoding.UTF8, "application/json")).ConfigureAwait(false))
                {
                    this.Logger.LogInformation($"Cookie being passed from {portalUrl + "/api/osr-authentication/login"}:{h.CookieContainer.GetCookies(new Uri(portalUrl + "/api/osr-authentication/login"))}");
                    if (loginResult.IsSuccessStatusCode)
                    {
                        var url = portalUrl + tenantLogin;
                        this.Logger.LogInformation($"Cookie being passed from {url}:{h.CookieContainer.GetCookies(new Uri(url))}");
                        using (var response = await c.GetAsync(url, HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false))
                        {
                            if (response.IsSuccessStatusCode)
                            {
                                using (var reader = new JsonTextReader(new StreamReader(await response.Content.ReadAsStreamAsync().ConfigureAwait(false))))
                                {
                                    var serializer = new JsonSerializer();
                                    var result = serializer.Deserialize<GatewayConnectionInfo>(reader);

                                    if (tenantId.HasValue)
                                    {
                                        try
                                        {
                                            await c.GetAsync(portalUrl + $"/api/portal/entertenantcontext?tenantId={tenantId}").ConfigureAwait(false);
                                        }
                                        catch (Exception ex)
                                        {
                                            this.Logger.LogError($"OSR Login Error: Error trying to switch to TenantId: {tenantId}. Error Message: {ex.Message}");
                                            throw;
                                        }
                                    }
                                    result.TenantId = tenantInfo.Id;
                                    result.TenantName = tenantInfo.Name;


                                    return result;
                                }

                            }

                            if (h.CookieContainer.GetCookies(new Uri(url)).Count == 0)
                                throw new Exception($"Error {response.StatusCode}, Authentication cookie was not found.");

                            throw new Exception($"Error {response.StatusCode}, {await response.Content.ReadAsStringAsync()}.");
                        }
                    }
                    throw new Exception($"Error {loginResult.StatusCode}, {await loginResult.Content.ReadAsStringAsync()}.");
                }
            }
        }
    }

    public class GatewayConnectionInfo
    {
        #region Public Properties
        public string CompanyName { get; set; }
        public Guid TenantId { get; set; }
        public string TenantName { get; set; }
        public string Signalrurl { get; set; }
        #endregion Public Properties
    }



    //Taken from https://stackoverflow.com/questions/1799370/getting-attributes-of-enums-value
    public static class EnumHelper
    {
        public static T GetAttributeOfType<T>(this Enum enumVal) where T : Attribute
        {
            var type = enumVal.GetType();
            var memInfo = type.GetMember(enumVal.ToString());
            var attributes = memInfo[0].GetCustomAttributes(typeof(T), false);
            return (attributes.Length > 0) ? (T)attributes[0] : null;
        }

        public static string GetAttributeDescription(this Enum enumValue)
        {
            var attribute = enumValue.GetAttributeOfType<DescriptionAttribute>();
            return attribute == null ? String.Empty : attribute.Description;
        }
    }
}
