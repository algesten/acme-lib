use crate::api::ApiProblem;

pub(crate) type HttpResult<T> = Result<T, ApiProblem>;


pub trait HttpResponse: Sized {
    fn body(self) -> String;
    fn header(&self, name: &str) -> HttpResult<&str>;

    fn handle_errors(self) -> HttpResult<Self>;
}

pub trait HttpClient: Clone + Sized {
    type Response: HttpResponse;

    fn get(&self, url: &str) -> Self::Response;
    fn head(&self, url: &str) -> Self::Response;
    fn post(&self, url: &str, body: &str) -> Self::Response;
}

