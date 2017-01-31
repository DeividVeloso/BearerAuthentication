using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace AuthenticacaoBearer
{
    public class AuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        //Valida o token no cahce que o Oath é responsavel, ele ve se o token existe lá e se é valido
        //Toda vez que fazemos uma requisição no servidor ele passa aqui antes para checar o token
        //Ele não vai no banco de dados ele verifica no cache do servidor.
        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            //Valida um token já existente
            context.Validated();
        }

        //Cria um token através dos dados do método service.Authenticate
        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            //Habilito o Cors
            //Sempre vem externo a chamada da API - * São os verbos aceitos
            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { "*" });

            try
            {
                var user = context.UserName;
                var password = context.Password;

                //Se for invalido retornar mensagem de erro
                if (user != "Deivid" || password != "123456" )
                {
                    context.SetError("invalid_grant", "senha inválida");
                    return;
                }

                //Começo a criar o ClaimsIdentity
                //É uma identidade para o usuário
                var identity = new ClaimsIdentity(context.Options.AuthenticationType);

                //O dado mais importante para identificar um usuário você coloca no ClaimTypes.Name
                identity.AddClaim(new Claim(ClaimTypes.Name, user));

                //Perfil do usuário
                var roles = new List<string>();
                roles.Add("User");

                foreach (var role in roles)
                {
                    identity.AddClaim(new Claim(ClaimTypes.Role, role));
                }
                

                //Gera a autenticação para Thread atual, senão colocar ele não autentica
                GenericPrincipal principal = new GenericPrincipal(identity, roles.ToArray());
                //Seta o usuário atual na Thread, não não setar não tenho como recuperar o usuário no controller
                Thread.CurrentPrincipal = principal;

                context.Validated(identity);
            }
            catch (Exception ex)
            {
                context.SetError("invalid_grant", "invalidos");
            }
        }
    }
}
