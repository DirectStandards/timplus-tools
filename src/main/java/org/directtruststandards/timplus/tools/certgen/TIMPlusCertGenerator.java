/* 
Copyright (c) 2010, NHIN Direct Project
All rights reserved.

Authors:
   Greg Meyer      gm2552@cerner.com
 
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer 
in the documentation and/or other materials provided with the distribution.  Neither the name of the The NHIN Direct Project (nhindirect.org). 
nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, 
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS 
BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE 
GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, 
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF 
THE POSSIBILITY OF SUCH DAMAGE.
*/

package org.directtruststandards.timplus.tools.certgen;

import java.awt.AWTEvent;
import java.awt.BorderLayout;
import java.awt.GraphicsEnvironment;
import java.awt.Image;
import java.awt.Point;
import java.security.Security;

import javax.swing.ImageIcon;
import javax.swing.JFrame;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;

/**
 * Simple Swing application for generating self signed certificates (CAs) and leaf certificates for TIM+.  The certificates generated are 
 * streamlined to simple uses cases: it does not support the numerous options supported using tools such as openssl. 
 * @author Greg Meyer
 * @since 1.0
 */
///CLOVER:OFF
@SpringBootApplication
public class TIMPlusCertGenerator extends JFrame
{
    static
    {
		Security.addProvider(new BouncyCastleProvider());
    }	
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -1362014092984111324L;
	private CAPanel certAuth;

    public static void main(String[] args) 
    {

        new SpringApplicationBuilder(TIMPlusCertGenerator.class)
                .headless(false).run(args);

		TIMPlusCertGenerator hi = new TIMPlusCertGenerator();
		hi.setVisible(true);
    }	
	
	
	public TIMPlusCertGenerator()
	{	
		super("TIM+ Certificate Generator");
		setDefaultLookAndFeelDecorated(true);
		setSize(700, 310);
		setResizable(false);
		
		Point pt = GraphicsEnvironment.getLocalGraphicsEnvironment().getCenterPoint();
		
		this.setLocation(pt.x - (150), pt.y - (120));			
		
	    enableEvents(AWTEvent.WINDOW_EVENT_MASK);
	    setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
	    
	    initUI();		
	}

	private void initUI()
	{
		final Image img = new ImageIcon(getClass().getResource("/images/cert.png")).getImage();
		this.setIconImage(img);
		
		
		getContentPane().setLayout(new BorderLayout());
		
		certAuth = new CAPanel();
		
		getContentPane().add(certAuth);
	}
}
///CLOVER:ON