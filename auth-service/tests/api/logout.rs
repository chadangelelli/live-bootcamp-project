use crate::helpers::TestApp;

#[tokio::test]
async fn logout_returns_200_status() {
    let app = TestApp::new().await;
    let response = app.get_path("/logout").await;

    assert_eq!(response.status().as_u16(), 200);
}
