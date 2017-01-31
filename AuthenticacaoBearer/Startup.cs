using Microsoft.Owin;
using Microsoft.Owin.Security.OAuth;
using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Http;

namespace AuthenticacaoBearer
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            //Precisa para configurar minha API
            HttpConfiguration config = new HttpConfiguration();

            ConfigureWebApi(config);

            //Deixa o serviço publico sem nenhuma restrição de acesso entre dominios diferentes
            //Configurações iniciais  para que meu serviço rode
            app.UseCors(Microsoft.Owin.Cors.CorsOptions.AllowAll);
            app.UseWebApi(config); //Informa que estou usando um WEBAPI
        }
        //Configuração obrigatória do WebAPI
        public static void ConfigureWebApi(HttpConfiguration config)
        {
            //Configura a rota padrão do WebAPI, esse mesmo código fica no arquivo WebApiConfig
            config.MapHttpAttributeRoutes();
            config.Routes.MapHttpRoute(
                    name: "DefaultApi",
                    routeTemplate: "api/{controller}/{id}",
                    defaults: new { id = RouteParameter.Optional }
                );
        }

        public void ConfigureOAuth(IAppBuilder app, IUserService service)
        {
            //Opções de autorização no meu servidor
            OAuthAuthorizationServerOptions OAuthServerOptions = new OAuthAuthorizationServerOptions()
            {
                //Permite chamadas inseguras Http
                AllowInsecureHttp = true,
                //Endpoint que gera um token através de um usuário e senha
                TokenEndpointPath = new PathString("/api/security/token"),
                //Esse token terar duração de 2 horas
                AccessTokenExpireTimeSpan = TimeSpan.FromHours(2),
                //Gera um token baseado no retorno da classe AuthorizationServerProvider
                Provider = new AuthorizationServerProvider(service)
            };
            // Token Generation
            app.UseOAuthAuthorizationServer(OAuthServerOptions);
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions());
        }
    }
}