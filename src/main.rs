use actix_files::{NamedFile};
use actix_web::cookie::CookieBuilder;
use actix_web::{post, web, App, HttpResponse, HttpServer, get, HttpRequest};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio_postgres::NoTls;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use sha2::{Digest, Sha256};
use dashmap::DashMap;
use dotenv::dotenv;

#[derive(Deserialize)]
struct User {
    id: i64,
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct UserLogin {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct UserUpdate {
    username: String,
    new_img: String,
    current_password: String,
    new_password: String,
}

#[derive(Debug, Clone, Serialize)]
struct SessionUser {
    id: i32,
    username: String,
    is_invited_user: bool,
    is_admin: bool,
}


struct Salt(Vec<u8>);

fn generate_salt() -> Salt {
    let mut salt = [0u8; 1];
    rand::thread_rng().fill(&mut salt);
    Salt(salt.to_vec())
}

fn hash_password(salt: &Salt, password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(&salt.0); // Add salt to hash
    let result = hasher.finalize();
    base64::encode(&result)
}

#[post("/sign_up")]
async fn sign_up(user: web::Json<User>, client: web::Data<Arc<tokio_postgres::Client>>) -> HttpResponse {
    
    if user.username.len() <= 5 {
        return HttpResponse::BadRequest().body("Username must be longer than 5 characters.");
    }
    
    // Check password length and content
    if user.password.len() <= 8 || !user.password.chars().any(|c| c.is_numeric()) || !user.password.chars().any(|c| c.is_alphabetic()) {
        return HttpResponse::BadRequest().body("Password must be longer than 8 characters and contain both numbers and alphabetic characters.");
    }
    
    if user.id <= 10000 {
        return HttpResponse::BadRequest().body("You cannot sign up as invited user. If you are a invited user please contact system admin to obtain your username/password.");
    }

    if user.id < 0 {
        return HttpResponse::BadRequest().body("ID must be positive.");
    }

    let user_id = user.id as i32;

    if user_id == 0 {
        return HttpResponse::BadRequest().body("You cannot signup as admin."); //Admin signup will be manual, /app/parity_decoded/gen_admin_server crate will handle the secure admin generation
    }

    let check_result = client
        .query(
            "SELECT * FROM users WHERE username = $1",
            &[&user.username],
        )
        .await;
    
    if let Ok(rows) = check_result {
        if !rows.is_empty() {
            return HttpResponse::BadRequest().body("This username is already registered.");
        }
    }

    let salt = generate_salt();
    let hashed_password = hash_password(&salt, &user.password);

    let result = client
        .execute(
            "INSERT INTO users VALUES ($1, $2, $3, $4)",
            &[&(user_id), &user.username, &hashed_password, &base64::encode(&salt.0)],
        )
        .await;
    
    // After successfully storing the user, we need to copy the profile picture
    if let Ok(_) = result {
        let image_copy_result = tokio::fs::copy("static/user.png", format!("static/{}.png", &user.username)).await;
        match image_copy_result {
            Ok(_) => HttpResponse::Created().body("Successfully signed up!"),
            Err(e) => HttpResponse::InternalServerError().body(format!("Failed to copy profile picture: {}", e.to_string())),
        }
    } else {
        HttpResponse::InternalServerError().body("Failed to sign up due to internal error.")
    }
}



#[post("/login")]
async fn login(
    user: web::Json<UserLogin>,
    sessions: web::Data<Arc<DashMap<String, Arc<SessionUser>>>>,
    client: web::Data<Arc<tokio_postgres::Client>>
) -> HttpResponse {

    // Query the user using id
    let result = client
        .query(
            "SELECT * FROM users WHERE username = $1",
            &[&user.username],
        )
        .await;
    match result {
        Ok(rows) => {
            if !rows.is_empty() {
                // Compare the passwords
                let salt = Salt(base64::decode(rows[0].get::<_, String>(3)).unwrap());
                let stored_password = hash_password(&salt, &user.password);
                if stored_password == rows[0].get::<_, String>(2) {
                    let id_val = rows[0].get::<_, i32>(0);
                    if id_val > 10000 {
                        return HttpResponse::BadRequest().body(
                            json!({
                                "error": "Only invited users can login at this time."
                            }).to_string()
                        );
                    }

                    // The password is correct, log in the user
                    // Generate salted hash for session_id
                    let mut hasher = Sha256::new();
                    hasher.update(user.password.as_bytes());
                    hasher.update(&salt.0); // Add salt to hash
                    let result = hasher.finalize();
                    let session_id = format!("{}{}{}", id_val, user.username, hex::encode(result));

                    // Check if session already exists
                    if id_val == 0 {
                        if sessions.get(&session_id).is_some() {
                            return HttpResponse::BadRequest().body(
                                json!({
                                    "error": "Admin already has a active session, multiple admin login is restricted."
                                }).to_string()
                            );
                        }
                    }
    
                    let session_user = SessionUser {
                        id: id_val,
                        username: user.username.clone(),
                        is_invited_user: id_val < 10000,
                        is_admin: id_val == 0,
                    };
                    sessions.insert(session_id.clone(), Arc::new(session_user));

                    let flag_result = client.query("SELECT code FROM flags WHERE number = 1", &[]).await;

                    match flag_result {
                        Ok(flag_rows) => {
                            if !flag_rows.is_empty() {
                                let flag_code = flag_rows[0].get::<_, String>(0);
                                let redirect_url = "/index";

                                HttpResponse::Ok()
                                    .append_header(("location", "/index"))
                                    .cookie(
                                        CookieBuilder::new("user", session_id)
                                            .secure(false)
                                            .http_only(false)
                                            .finish(),
                                    )
                                    .cookie(
                                        CookieBuilder::new("flag_1", flag_code)
                                            .secure(false)
                                            .http_only(false)
                                            .finish(),
                                    )
                                    .body(
                                        json!({
                                            "redirect": redirect_url
                                        }).to_string()
                                    )
                            } else {
                                // Flag not found
                                HttpResponse::InternalServerError().body(
                                    json!({
                                        "error": "Flag not found"
                                    }).to_string()
                                )
                            }
                        }
                        Err(_) => HttpResponse::InternalServerError().body(
                            json!({
                                "error": "Failed to query flag"
                            }).to_string()
                        ),
                    }
                    
                } else {
                    // The password is incorrect
                    HttpResponse::Unauthorized().body(
                        json!({
                            "error": "Invalid username or password"
                        }).to_string()
                    )
                }
            } else {
                // The user does not exist
                HttpResponse::Unauthorized().body("Invalid username or password")
            }
        }
        Err(_) => HttpResponse::InternalServerError().body(
            json!({
                "error": "Failed to query user"
            }).to_string()
        ),
    }
}


#[post("/get_new_user_id")]
async fn get_new_user_id(client: web::Data<Arc<tokio_postgres::Client>>) -> HttpResponse {
    let result = client.query("SELECT COUNT(*) FROM users", &[]).await;
    match result {
        Ok(rows) => {
            let user_count: i64 = rows[0].get(0);
            let new_user_id = user_count + 10000; //First 10000 is reserved for invited users
            HttpResponse::Ok().json(new_user_id)
        },
        Err(_) => HttpResponse::InternalServerError().body("Failed to query user count"),
    }
}



#[post("/get_user_info")]
async fn get_user_info(
    req: HttpRequest,
    sessions: web::Data<Arc<DashMap<String, Arc<SessionUser>>>>,
) -> HttpResponse {
    if let Some(cookie) = req.cookie("user") {
        if let Some(session) = sessions.get(&cookie.value().to_string()) {
            // Clone the session user data
            let user_data = SessionUser {
                id: session.id,
                username: session.username.clone(),
                is_invited_user: session.is_invited_user,
                is_admin: session.is_admin,
            };

            return HttpResponse::Ok().json(user_data);
        } else {
            // The session does not exist
            return HttpResponse::BadRequest().body("Session not found");
        }
    }
    HttpResponse::PermanentRedirect().append_header(("location", "/login"))
        .finish()
}

#[post("/online_users")]
async fn online_users(
    sessions: web::Data<Arc<DashMap<String, Arc<SessionUser>>>>,
) -> HttpResponse {
    let mut users: Vec<SessionUser> = Vec::new();
    for user in sessions.iter() {
        let user_data = SessionUser {
            id: user.id,
            username: user.username.clone(),
            is_invited_user: user.is_invited_user,
            is_admin: user.is_admin,
        };
        users.push(user_data);
    }
    HttpResponse::Ok().json(users)
}

#[post("/update_profile")]
async fn update_profile(
    req: HttpRequest,
    user: web::Json<UserUpdate>,
    client: web::Data<Arc<tokio_postgres::Client>>,
    sessions: web::Data<Arc<DashMap<String, Arc<SessionUser>>>>,
) -> HttpResponse {
    if let Some(cookie) = req.cookie("user") {
        if let Some(session) = sessions.get(&cookie.value().to_string()) {
            if session.id == 0 {
                return HttpResponse::BadRequest().body("Cannot change admin password.");
            }

            // Check if new username is already taken (unless it's the same as the current one)
            if user.username != session.username {
                let check_result = client
                    .query(
                        "SELECT * FROM users WHERE username = $1",
                        &[&user.username],
                    )
                    .await;
                if let Ok(rows) = check_result {
                    if !rows.is_empty() {
                        return HttpResponse::BadRequest().body("This username is already registered.");
                    }
                }
            }

            // Check if the current password is correct
            let result = client
                .query(
                    "SELECT password, salt FROM users WHERE id = $1",
                    &[&session.id],
                )
                .await;

            if let Ok(rows) = result {
                if !rows.is_empty() {
                    let stored_password: String = rows[0].get(0);
                    let stored_salt: String = rows[0].get(1);
                    let hashed_input_password = hash_password(&Salt(base64::decode(&stored_salt).unwrap()), &user.current_password);
                    if stored_password != hashed_input_password {
                        return HttpResponse::BadRequest().body("Current password is incorrect.");
                    }
                }
            }

            let salt = generate_salt();
            let hashed_password = hash_password(&salt, &user.new_password);

            let result = client
                .execute(
                    "UPDATE users SET username = $1, password_hash = $2, salt = $3 WHERE id = $4",
                    &[&user.username, &hashed_password, &base64::encode(&salt.0), &session.id],
                )
                .await;

            // Now handle the image update.
            // First, decode the base64 string into bytes.
            let img_bytes = base64::decode(&user.new_img);
            if img_bytes.is_err() {
                return HttpResponse::BadRequest().body("Image data is not a valid base64 string.");
            }
            let img_bytes = img_bytes.unwrap();

            // Then write these bytes to a file.
            let file_path = format!("static/{}.png", &user.username);
            let result = tokio::fs::write(file_path, img_bytes).await;
            if result.is_err() {
                return HttpResponse::InternalServerError().body("Failed to update profile image.");
            }

            match result {
                Ok(_) => HttpResponse::Ok().body("Profile updated successfully."),
                Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
            }
        } else {
            // The session does not exist
            HttpResponse::BadRequest().body("Session not found.")
        }
    } else {
        HttpResponse::Unauthorized().body("Not authorized.")
    }
}




#[post("/user_profile")]
async fn user_profile(
    req: HttpRequest,
    sessions: web::Data<Arc<DashMap<String, Arc<SessionUser>>>>,
    profile_pic_path: web::Json<HashMap<String, String>>,
) -> actix_web::Result<HttpResponse> {
    if let Some(cookie) = req.cookie("user") {
        if let Some(session) = sessions.get(&cookie.value().to_string()) {
            // Clone the session user data
            let user_data = SessionUser {
                id: session.id,
                username: session.username.clone(),
                is_invited_user: session.is_invited_user,
                is_admin: session.is_admin,
            };

            if user_data.is_invited_user || user_data.is_admin {
                let path = format!("static/{}", profile_pic_path.get("imgPath").unwrap_or(&"".to_string()));
                if Path::new(&path).exists() {
                    let mut file = File::open(path)?;
                    let mut buffer: Vec<u8> = Vec::new();
                    file.read_to_end(&mut buffer)?;

                    Ok(HttpResponse::Ok().content_type("image/jpeg").body(buffer))
                } else {
                    Ok(HttpResponse::NotFound().json(json!({ "error": "Image not found" })))
                }
            } else {
                Ok(HttpResponse::Unauthorized().json(json!({ "error": "You are not authorized to access this page" })))
            }
        } else {
            // The session does not exist
            Ok(HttpResponse::Unauthorized().json(json!({ "error": "Session not found" })))
        }
    } else {
        Ok(HttpResponse::Unauthorized().json(json!({ "error": "No session cookie found" })))
    }
}

#[derive(Deserialize)]
struct FlagData {
    email: String,
    flag: String,
}

#[post("/flag")]
async fn post_flag(
    data: web::Json<FlagData>,
    client: web::Data<Arc<tokio_postgres::Client>>
) -> HttpResponse {
    // Extract the JSON data
    let FlagData { email, flag } = data.into_inner();

    // Check if the flag exists
    let flag_in_db = client.query("SELECT * FROM flags WHERE code=$1", &[&flag]).await;
    match flag_in_db {
        Ok(rows) => {
            if !rows.is_empty() {
                // Check if the flag was submitted before by the same email
                let flag_already_submitted = client.query("SELECT * FROM submits WHERE email=$1 AND flag_number=(SELECT number FROM flags WHERE code=$2)", &[&email, &flag]).await;
                
                match flag_already_submitted {
                    Ok(submit_rows) => {
                        if submit_rows.is_empty() {
                            // Insert the flag submission into the database
                            match client.execute("INSERT INTO submits (email, flag_number) VALUES ($1, (SELECT number FROM flags WHERE code=$2))", &[&email, &flag]).await {
                                Ok(_) => {
                                    // Return the flag message
                                    let flag_message: String = rows[0].get("message");
                                    HttpResponse::Ok().json(flag_message)
                                },
                                Err(_) => HttpResponse::InternalServerError().body("Failed to submit flag"),
                            }
                        } else {
                            HttpResponse::BadRequest().body("Flag was already submitted")
                        }
                    },
                    Err(_) => HttpResponse::InternalServerError().body("Failed to check if flag was already submitted"),
                }
            } else {
                HttpResponse::BadRequest().body("Invalid flag")
            }
        },
        Err(_) => HttpResponse::InternalServerError().body("Failed to query flag"),
    }
}




#[get("/")]
async fn root_page(
    req: HttpRequest,
    sessions: web::Data<Arc<DashMap<String, Arc<SessionUser>>>>,
) -> HttpResponse {
    if let Some(cookie) = req.cookie("user") {
        if let Some(session) = sessions.get(&cookie.value().to_string()) {
            match (session.is_invited_user, session.is_admin) {
                (true, false) => return HttpResponse::SeeOther().append_header(("location", "/index")).finish(),
                (false, false) => return HttpResponse::SeeOther().append_header(("location", "/login")).finish(),
                (_, true) => return HttpResponse::SeeOther().append_header(("location", "/admin")).finish(),
            }
        }
    }
    HttpResponse::SeeOther().append_header(("location", "/login")).finish()
}

#[get("/user_profile")]
async fn profile_page() -> actix_web::Result<NamedFile> {
    Ok(NamedFile::open("static/user_profile.html")?)
}

#[get("/login")]
async fn login_page() -> actix_web::Result<NamedFile> {
    Ok(NamedFile::open("static/login.html")?)
}

#[get("/flag")]
async fn flag_page() -> actix_web::Result<NamedFile> {
    Ok(NamedFile::open("static/flag.html")?)
}

#[get("/admin")]
async fn admin_page(
    req: HttpRequest,
    sessions: web::Data<Arc<DashMap<String, Arc<SessionUser>>>>,
) -> actix_web::Result<NamedFile> {
    if let Some(cookie) = req.cookie("user") {
        if let Some(session) = sessions.get(&cookie.value().to_string()) {
            match (session.is_invited_user, session.is_admin) {
                (true, false) => HttpResponse::SeeOther().append_header(("location", "/index")).finish(),
                (false, false) => HttpResponse::SeeOther().append_header(("location", "/login")).finish(),
                (_ , _) => HttpResponse::Ok().into(),
            };
        }
    }
    Ok(NamedFile::open("static/admin.html")?)
}

#[get("/index")]
async fn index_page(
    req: HttpRequest,
    sessions: web::Data<Arc<DashMap<String, Arc<SessionUser>>>>,
) -> actix_web::Result<NamedFile> {

    if let Some(cookie) = req.cookie("user") {
        if let Some(session) = sessions.get(&cookie.value().to_string()) {
            match (session.is_invited_user, session.is_admin) {
                (true, false) => HttpResponse::SeeOther().append_header(("location", "/index")).finish(),
                (false, false) => HttpResponse::SeeOther().append_header(("location", "/login")).finish(),
                (_, true) => HttpResponse::SeeOther().append_header(("location", "/admin")).finish(),
            };
        }
    }

    Ok(NamedFile::open("static/index.html")?)
}



#[get("/sign_up")]
async fn signup_page() -> actix_web::Result<NamedFile> {
    Ok(NamedFile::open("static/sign_up.html")?)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let dbname = dotenv::var("POSTGRES_DBNAME").unwrap();
    let dbhost = dotenv::var("POSTGRES_DBHOST").unwrap();
    let dbuser = dotenv::var("POSTGRES_DBUSER").unwrap();
    let dbpass = dotenv::var("POSTGRES_DBPASS").unwrap();

    let conn_str: Vec<String> = vec![String::from("host="), dbhost, String::from(" user="), dbuser, String::from(" password="), dbpass, String::from(" dbname="), dbname];
    let (client, connection) = tokio_postgres::connect(conn_str.concat().as_str(), NoTls).await.unwrap();

    let client = Arc::new(client);
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {}", e);
        }
    });

    let sessions: Arc<DashMap<String, Arc<SessionUser>>> = Arc::new(DashMap::new());

        
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(client.clone()))
            .app_data(web::Data::new(sessions.clone()))
            .service(sign_up)
            .service(login)
            .service(index_page)
            .service(login_page)
            .service(root_page)
            .service(signup_page)
            .service(get_new_user_id)
            .service(online_users)
            .service(get_user_info)
            .service(user_profile)
            .service(update_profile)
            .service(profile_page)
            .service(post_flag)
            .service(flag_page)
            .service(admin_page)
            
    })
    .worker_max_blocking_threads(6000)
    .max_connection_rate(512)
    .bind("0.0.0.0:8081")?
    .run()
    .await
}



