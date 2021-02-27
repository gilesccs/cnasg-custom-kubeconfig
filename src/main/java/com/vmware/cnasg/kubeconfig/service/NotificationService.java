package com.vmware.cnasg.kubeconfig.service;

import java.io.File;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.FileSystemResource;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;



@Service
public class NotificationService {
	
	@Autowired
	private JavaMailSender javaMailSender;
	
	@Value("${spring.mail.username}")
	private String hostEmail;
	
//	@Autowired
//	public NotificationService(JavaMailSender javaMailSender) {
//		this.javaMailSender = javaMailSender;
//	}
		
	public void sendKubeConfigNotification(String path){
		
//		SimpleMailMessage mail = new SimpleMailMessage();
//		mail.setTo(user.getEmail());
//		mail.setFrom(hostEmail);
//		mail.setSubject("Your Default Password");
//		String emailText = "Dear admin, \n\nPlease note that your default is " + user.getPassword() +  ". \n\nYou may also wish to change your password as well. " + " \n\nPlease do not reply to "
//						+ "this automated email.\n\n" + "Regards,\nVMWare Team";
//		mail.setText(emailText);
//	
//		javaMailSender.send(mail);
		System.out.println("email cp1");
		MimeMessage message = javaMailSender.createMimeMessage();
	     
	    MimeMessageHelper helper;
		try {
			helper = new MimeMessageHelper(message, true);
			helper.setFrom(hostEmail);
		    helper.setTo("giles.chang.2018@sis.smu.edu.sg");
		    helper.setSubject("Kubeconfig file generated");
		    helper.setText("testing hi pls download");
		    System.out.println("here");
		    FileSystemResource file 
		      = new FileSystemResource(new File(path));
		    helper.addAttachment("KubeConfigFile.yaml", file);

		    javaMailSender.send(message);
		} catch (MessagingException e) {
			// TODO Auto-generated catch block
			System.out.println("fail email");
			e.printStackTrace();
		}
		
	}
}
