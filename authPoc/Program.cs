using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

var AllowAll = "_allowAll";

builder.Services.AddCors(options =>
{
	options.AddPolicy(name: AllowAll,
		policy =>
		{
			policy.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader();
		});
});

// Add services to the container.
builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();
app.UseCors(AllowAll);
// Configure the HTTP request pipeline.
app.UseSwagger();
app.UseSwaggerUI();

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();


app.MapPost("/login", [AllowAnonymous] (User user) =>
{
	var users = new List<User>
	{
		new User { Id = 1, Email = "thibaut.humblet@uza.be", Password = "test123", Name = "Thibaut Humblet", Login = "x051240" },
		new User { Id = 2, Email = "els.wittesaele@uza.be", Password = "test123", Name = "Els Wittesaele", Login = "ed81" },
	};

	if (users.Any(u => u.Email == user.Email && u.Password == user.Password))
	{
		var login = users.Where(x => x.Email.Equals(user.Email)).Select(x => x.Login).FirstOrDefault();
		login ??= "Unknown";
		var issuer = builder.Configuration["Jwt:Issuer"];
		var audience = builder.Configuration["Jwt:Audience"];
		string? key = builder.Configuration.GetValue<string>("Jwt:Key");
		key ??= string.Empty;
		var tokenDescriptor = new SecurityTokenDescriptor
		{
			Subject = new ClaimsIdentity(new[]
			{
				new Claim("Id", Guid.NewGuid().ToString()),
				new Claim(JwtRegisteredClaimNames.Sub, user.Email),
				new Claim(JwtRegisteredClaimNames.Email, user.Email),
				new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
				new Claim(JwtRegisteredClaimNames.UniqueName, login)
			}),
			Expires = DateTime.UtcNow.AddMinutes(60),
			Issuer = issuer,
			Audience = audience,
			SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)), SecurityAlgorithms.HmacSha512Signature)
		};

		var tokenHandler = new JwtSecurityTokenHandler();
		var token = tokenHandler.CreateToken(tokenDescriptor);
		var jwtToken = tokenHandler.WriteToken(token);
		var stringToken = tokenHandler.WriteToken(token);
		return Results.Ok(stringToken);
	}
	return Results.Unauthorized();
});

app.Run();


public class User
{
	public int Id { get; set; }
	public string Email { get; set; } = string.Empty;
	public string Password { get; set; } = string.Empty;
	public string Name { get; set; } = string.Empty;
	public string Login { get; set; } = string.Empty;

}
