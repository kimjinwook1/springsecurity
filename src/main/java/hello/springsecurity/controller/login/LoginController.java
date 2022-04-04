package hello.springsecurity.controller.login;

import hello.springsecurity.domain.Account;
import hello.springsecurity.security.token.AjaxAuthenticationToken;
import java.security.Principal;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class LoginController {

	@GetMapping("/login")
	public String login(@RequestParam(value = "error", required = false) String error,
		@RequestParam(value = "exception", required = false) String exception,
		Model model) {
		model.addAttribute("error", error);
		model.addAttribute("exception", exception);
		return "user/login/login";
	}

	@GetMapping("/logout")
	public String logout(HttpServletRequest request, HttpServletResponse response) {

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		if (authentication != null) {
			new SecurityContextLogoutHandler().logout(request, response, authentication);
		}
		return "user/login/login";
	}
//
//	@GetMapping("/denied")
//	public String accessDenied(@RequestParam(value = "exception", required = false) String exception, Model model, HttpSession session) {
//		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//		System.out.println("authentication.getPrincipal() = " + authentication.getPrincipal());
//		Account account = new Account();
//		if (authentication.getPrincipal() instanceof Account) {
//			account = (Account) authentication.getPrincipal();
//		}
//		if (!(authentication.getPrincipal() instanceof Account)) {
//			account = (Account) session.getAttribute("loginMember");
//			System.out.println("account = " + account);
//		}
//		model.addAttribute("username", account.getUsername());
//		model.addAttribute("exception", exception);
//
//		return "user/login/denied";
//	}

	@GetMapping(value={"/denied","/api/denied"})
	public String accessDenied(@RequestParam(value = "exception", required = false) String exception, Principal principal, Model model) throws Exception {

		Account account = null;

		if (principal instanceof UsernamePasswordAuthenticationToken) {
			account = (Account) ((UsernamePasswordAuthenticationToken) principal).getPrincipal();

		}else if(principal instanceof AjaxAuthenticationToken){
			account = (Account) ((AjaxAuthenticationToken) principal).getPrincipal();
		}
		model.addAttribute("username", account.getUsername());
		model.addAttribute("exception", exception);

		return "user/login/denied";
	}
}
