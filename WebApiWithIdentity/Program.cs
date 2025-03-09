using Azure.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.MicrosoftAccount;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;
using System.Text;
using WebApiWithIdentity.Data;
using WebApiWithIdentity.Models;
using WebApiWithIdentity.Services;

var builder = WebApplication.CreateBuilder(args);

// Core Services
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

builder.Services.AddScoped<TokenService>();

// Load configuration from appsettings.json
builder.Configuration.AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                      .AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true)
                      .AddEnvironmentVariables();

// Use User Secrets in Development
if (builder.Environment.IsDevelopment())
{
    builder.Configuration.AddUserSecrets<Program>();
}
else
{
    // Use Azure Key Vault in Test and Production
    var keyVaultUrl = builder.Configuration["KeyVault:Url"];
    if (!string.IsNullOrEmpty(keyVaultUrl))
    {
        var credential = new DefaultAzureCredential(); // Uses Managed Identity or Azure credentials
        builder.Configuration.AddAzureKeyVault(new Uri(keyVaultUrl), credential);
    }
}

// Database Configuration
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Identity Configuration
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// Authentication Configuration
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
    .AddJwtBearer(options => ConfigureJwtBearer(options, builder.Configuration))
    .AddCookie(options => ConfigureCookies(options))
    .AddGoogle(options => ConfigureGoogleAuth(options, builder.Configuration))
    .AddMicrosoftAccount(options => ConfigureMicrosoftAuth(options, builder.Configuration));

// CORS Configuration
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAngularApp", policy =>
    {
        policy.WithOrigins(builder.Configuration["ClientUrl"])
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials()
              .SetIsOriginAllowed(_ => true); // Consider removing in production
    });
});

// Controller and Authorization Services
builder.Services.AddControllers();
builder.Services.AddAuthorization();

// Swagger Configuration
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options => ConfigureSwagger(options));

var app = builder.Build();

// Middleware Pipeline
app.UseHttpsRedirection();
app.UseCors("AllowAngularApp");

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseSession();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();

// Configuration Methods
static void ConfigureJwtBearer(JwtBearerOptions options, IConfiguration config)
{
    options.SaveToken = true;
    options.RequireHttpsMetadata = false; // Note: Use true in production
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateAudience = false, // Consider enabling in production
        ValidateIssuer = false,   // Consider enabling in production
        ValidAudience = config["JWT:ValidAudience"],
        ValidIssuer = config["JWT:ValidIssuer"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["JWT:Secret"]))
    };
}

static void ConfigureCookies(CookieAuthenticationOptions options)
{
    options.Cookie.SameSite = SameSiteMode.None;
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // Consider in production
}

static void ConfigureGoogleAuth(GoogleOptions options, IConfiguration config)
{
    options.ClientId = config["Authentication:Google:ClientId"];
    options.ClientSecret = config["Authentication:Google:ClientSecret"];
    options.SignInScheme = IdentityConstants.ExternalScheme;
    options.SaveTokens = true;    
    options.Scope.Add("profile");
    options.Scope.Add("email");
    options.ClaimActions.MapJsonKey("urn:google:picture", "picture", "url");
}

static void ConfigureMicrosoftAuth(MicrosoftAccountOptions options, IConfiguration config)
{
    options.ClientId = config["Authentication:Microsoft:ClientId"];
    options.ClientSecret = config["Authentication:Microsoft:ClientSecret"];
    options.SignInScheme = IdentityConstants.ExternalScheme;
    options.SaveTokens = true;
    options.Scope.Add("User.Read");
    options.ClaimActions.MapJsonKey("urn:microsoft:picture", "picture", "url");
}

static void ConfigureSwagger(SwaggerGenOptions options)
{
    options.SwaggerDoc("v1", new OpenApiInfo { Title = "WebApiWithIdentity", Version = "v1" });
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT"
    });
    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
}