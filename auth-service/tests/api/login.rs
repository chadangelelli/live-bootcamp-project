use crate::helpers::TestApp;

#[tokio::test]
async fn login_returns_200_status() {
    let app = TestApp::new().await;
    let response = app.get_path("/login").await;

    assert_eq!(response.status().as_u16(), 200);
}
