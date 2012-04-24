% emi.cls: 
% Branched from egee.cls 1.6 
% revision 2.0 [based on word template]
% Emidio Giorgio -- emidio.giorgio@ct.infn.it 
% March 31, 2011 

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% License 
%
% This work is licensed under Creative Commons Attribution-ShareAlike 3.0.
% 		http://creativecommons.org/licenses/by/3.0/
% You are free:
%   * to Share Ñ to copy, distribute and transmit the work
%   * to Remix Ñ to adapt the work
%
% Under the following conditions:
%   * Attribution. You must attribute the work in the manner specified by the author or licensor 
% (but not in any way that suggests that they endorse you or your use of the work).
%   * Share Alike. If you alter, transform, or build upon this work, you may distribute the resulting 
% work only under the same, similar or a compatible license.
%   
%   * For any reuse or distribution, you must make clear to others the license terms of this work. 
% The best way to do this is with a link to this web page : http://creativecommons.org/licenses/by/3.0/
%   * Any of the above conditions can be waived if you get permission from the copyright holder.
%   * Nothing in this license impairs or restricts the author's moral rights.
%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{emi}[2011/03/24 EMI LaTeX Class]
\typeout{EMI LaTeX class -- 2011/03/24}
%
%% Interface - example of an option, should we want to use these later.
%\newif\ifmonotitle\monotitlefalse

%\DeclareOption{mono}{\monotitletrue}

\DeclareOption*{\PassOptionsToClass{\CurrentOption}{article}}
\ProcessOptions


% Inherit!
\LoadClass[11pt]{article}

% Necessary packages:
\RequirePackage{lastpage}
\RequirePackage{tabularx}
\RequirePackage{pslatex}
\RequirePackage{times}
\RequirePackage{verbatim}
\RequirePackage{geometry}
\RequirePackage{url}

\usepackage[hang,bf,small]{caption}
\usepackage[T1]{fontenc}
\usepackage[scaled]{helvet}
\usepackage{multirow}
\renewcommand*\familydefault{\sfdefault}
%
% We now define a new \if command to test for PDF being enabled.
% It is important because loading graphicx overrides the definition
% of \pdfoutput and sets it to true even when PDF is not enabled.
% Use \ifpdf instead of \ifx\pdfoutput\undefined hereafter.
%

\newif\ifpdf
\ifx\pdfoutput\undefined
        \pdffalse
        % \typeout{PDF _not_ defined}
\else
        \pdfoutput=1
        \pdftrue
        % \typeout{PDF _is_ defined}
\fi

\ifpdf
        \usepackage[pdftex,
                pdfpagemode={UseOutlines},bookmarks=true,bookmarksopen=true,
                bookmarksopenlevel=0,bookmarksnumbered=true,
                hypertexnames=false,colorlinks,linkcolor={blue},
                citecolor={blue},urlcolor={red},
                pdfstartview={FitV}]{hyperref}
\else
        \usepackage[hypertex]{hyperref}
\fi
    
\ifpdf
        \usepackage[pdftex]{graphicx}
        \pdfcompresslevel 9
        \pdfadjustspacing 1
\else
        \usepackage[dvips]{graphicx}
\fi

\usepackage{color}

\def\footsize{5mm}

%%
%% PAGE GEOMETRY DEFINITIONS
%%
% From Template file
\geometry{centering,includeheadfoot}
%\geometry{a4paper,top=12.5mm,headheight=12.5mm,headsep=5mm,foot=\footsize,footskip=13.3mm,bottom=12.5mm}
\geometry{a4paper,top=15.5mm,headheight=20mm,headsep=5mm,foot=\footsize,footskip=13.3mm,bottom=12.5mm}
\geometry{right=25mm,left=25mm}



% APM -- I don't think these are right, my impression is above is correct
%\geometry{a4paper,margin=0.98in,headheight=0.72in}


%%
%% PAGE COLOUR DEFINITIONS
%%



% paulm's prefered name ...
\def\bibname{References}

\setlength{\parindent}{0pt}
\setlength{\parskip}{1.4mm plus 0.4mm minus 0.2mm}

\def\@defaultfooter{
  \def\@oddfoot{\vbox to \footsize {%
    {\color{blue}\hrule width \textwidth height 1pt depth 0pt}%
    \vfil
    %\small\hbox to \textwidth{\ISTNumber%
    \small\hbox to \textwidth{%
                %\hfil
                %\hbox{\colorbox{yellow}{\MakeUppercase{\@Dissemination}}}%
                \hfil
                \hbox{\thepage/\pageref{LastPage}}}%
    }%
  }%
}


\def\ps@title{%
  \@defaultfooter
  \def\@oddhead{\hbox to \textwidth{\EMILogo\hfil\LargeCESNETLogo}}
}

\def\ps@headings{%
  \@defaultfooter
  \def\@oddhead{\vbox to \headheight{%
%\hrule width \textwidth height 1pt\relax
      \vbox to 0.75\headheight{%
        \hbox to \textwidth{%
          \hbox to 0pt{\EMILogo\hss}%
          \hfil

%%          \hbox to 8cm{%
%%            \vbox to 0.75\headheight{%
%%              \vfil
%%              \parbox{8cm}{%
%%                \centering\color{blue}%
%%                 \textbf{\MakeUppercase{\@title}}%
%% %\ifx\@Subtitle\@empty\else
%% %              \par\textbf{\scriptsize\@Subtitle}%
%% %\fi
%%  }%
%%              \vfil
%%            }%
%%          \hss}%

         \hfil
%\hbox to 0pt{\vrule width 1pt height 10pt depth 0pt \hss}%
%%           {\scriptsize\setlength{\parskip}{0pt}\setlength{\topsep}{0pt}%
%% %              \vbox to 0.75\headheight{%
%%                   \parbox{4cm}{x%
%%                       \begin{flushright}%
%%                           \textit{Doc. Identifier}:\\
%%                        \textbf{\@DocIdentifier}\\
%%                           \vfil
%%                           \textit{Date}: \textbf{\@Date}
%%                       \end{flushright}%
%%                   }%
%% %              }%
%%           }%

\hbox to 0pt{\hss\vbox to 0.75\headheight{%\hrule
\small
\parfillskip0pt
\leftskip 0pt plus 1fil
\parskip0ex
\textsc{Title}:
\par
\textbf{\@title}


\textit{Date}: \textbf{\@Date}
\vfil
%\hrule
}}%
%          \hbox to 4cm{\scriptsize
%            \vbox to 0.75\headheight{%
%              \parbox{4cm}{
%              \halign{\hfill####\cr
%                \textit{Doc. Identifier}:\cr
%               \textbf{\@DocIdentifier}\cr
%             % \noalign{\vfil}
%                \textit{Date}: \textbf{\@Date}\cr
%              }}%
%              \vfil
%            }%
%         }%
        }%
      }%
%\hrule width \textwidth height 1pt\relax
      \vfil\vskip 2.5mm\relax
      {\color{blue}\hrule width \textwidth height 1pt depth 0pt}%
    }%
  }%
}

\pagestyle{headings}

\setlength{\captionmargin}{1cm}

% image file extensions respective to the output format
\ifpdf
        \DeclareGraphicsExtensions{.jpg,.pdf,.png}
        \pdfcompresslevel=9
	\pdfinfo{ /Title (EMI) }
\else   
        \DeclareGraphicsExtensions{.eps}
\fi

\def\frontboxwidth{11cm}%

\definecolor{MyTeal}{rgb}{0,0.46,0.46}
\definecolor{blue}{rgb}{0.05,0.26,0.5}
%\definecolor{blue}{rgb}{0.1,0.1,0.5} %% egee blue
\definecolor{lightgrey}{gray}{0.65}

%%
%% Define our title page
%%
\AtBeginDocument{
\pagestyle{title}%
\hbox{}% Force top of page
\vfill
{\centering
        \fontsize{30}{50}{\textbf{\textsc{\textcolor{blue}{European Middleware Initiative}}}}\\[40mm]%
        %\Huge{\textbf{\textsc{\textcolor{blue}{European Middleware Initiative}}}}\\[20mm]%

        \fontsize{22}{28}{\textbf{\textsc{\@title}}}\\[2mm]%
        %\ifx\@Subtitle\@empty\else
        %    \normalsize\textsf{\@Subtitle}\\[10mm]%
        %\fi
}
\vfill

\begin{center}
\hbox to \textwidth{
     
      \vbox{
     
      {\color{MyTeal}\hrule width \frontboxwidth height 1mm depth 0pt}  
      
      \hbox to \frontboxwidth{\sf
      \begin{tabularx}{\frontboxwidth}{l>{\raggedright\arraybackslash}X} 
\\ 
                Document version: & \textbf{\@DocVersion}\\[3mm]
                EMI Component Version: & \textbf{\@EMICompVersion}\\[3mm]
                Date: & \textbf{\@Date}\\[3mm]
                %Document status: & \textbf{\@DocStatus}\\[3mm]
                
      \end{tabularx}
  
     }
     
       {\color{MyTeal}\hrule width \frontboxwidth height 1mm depth 0pt}
     %}%centering
     }

}
\end{center}

%\vfill
%{\sf\underline{Abstract}: \@Abstract}
\vfill
\newpage  % end of the first page
\pagestyle{headings}
\setcounter{tocdepth}{3}
} % End of AtBeginningDocument


%
% EMI style small-capital section titles.
%
% The numbering is aligned with the WinWord style, 
% although it is not common in the english typography...
%
\newcommand{\sectionbreak}{\newpage}
%\renewcommand{\thesection}{\arabic{section}.}
%\renewcommand{\thesubsection}{\thesection\arabic{subsection}.}
%\renewcommand{\thesubsubsection}{\thesubsection\arabic{subsubsection}.}

\renewcommand\section{\@startsection {section}{1}{\z@}%
                                   {-3.5ex \@plus -1ex \@minus -.2ex}%
                                   {2.3ex \@plus.2ex}%
                                   {\normalfont\Large\bfseries\sffamily\scshape}}

\renewcommand\subsection{\@startsection{subsection}{2}{\z@}%
                                     {-3.25ex\@plus -1ex \@minus -.2ex}%
                                     {1.5ex \@plus .2ex}%
                                     {\normalfont\large\bfseries\sffamily\scshape}}
\renewcommand\subsubsection{\@startsection{subsubsection}{3}{\z@}%
                                     {-3.25ex\@plus -1ex \@minus -.2ex}%
                                     {1.5ex \@plus .2ex}%
                                     {\normalfont\normalsize\bfseries\sffamily\scshape}}



%% APM NEED TO REDEFINE section
%\titleformat{\section}{\Large\bfseries\sffamily\scshape}{\thesection}{1em}{}
%\titlecontents{section} [2em] {\vspace*{4pt}}
%       {\large \sc \bfseries \contentslabel{2em}}
%       {\large \sc \bfseries \hspace*{-2em}}
%       {\large \textbf{\titlerule*[1ex]{.}\contentspage}} [\vspace*{4pt}]

%\titleformat{\subsection}{\large\bfseries\sffamily\scshape}{\thesubsection}{1em}{}
%\titlecontents{subsection} [5em] {}
%       {\sc \contentslabel{3em}}
%       {\sc \hspace*{-3em}}
%       {\titlerule*[1ex]{.}\contentspage} 


%
% common constants
%
%\def\ISTNumber{INFSO-RI-508833}
\newsavebox{\@EMILogo}
%\savebox{\@EMILogo}{\includegraphics[height=0.75\headheight]{EMI_Logo_std}}
\savebox{\@EMILogo}{\includegraphics[height=0.95\headheight]{EMI_Logo_std}}
\def\EMILogo{\usebox{\@EMILogo}}
%\def\LargeEMILogo{\includegraphics[height=\headheight]{EMI_Logo_std}}
\def\SmallEMILogo{\includegraphics[height=\headheight]{EMI_Logo_std}}
\def\LargeCESNETLogo{\includegraphics[height=\headheight]{cesnet}}
% DEL \def\ISTLogo{\includegraphics[height=\headheight]{isi}}

%
% parameters to be supplied by the author
%
% EG : subtitle seems no more needed
%\def\Subtitle#1{\gdef\@Subtitle{#1}}
%\gdef\@Subtitle{\@latex@warning@no@line{No \noexpand\Subtitle given}}

%\def\DeliverableId#1{\gdef\@DeliverableId{#1}}
%\gdef\@DeliverableId{\@latex@warning@no@line{No \noexpand\DeliverableId given}}

        
\def\DocVersion#1{\gdef\@DocVersion{#1}}
\gdef\@DocVersion{\@latex@warning@no@line{No \noexpand\DocVersion given %
        (e.g. 0.1.2)}}

\def\EMICompVersion#1{\gdef\@EMICompVersion{#1}}
\gdef\@EMICompVersion{\@latex@warning@no@line{No \noexpand\EMICompVersion given %
        (e.g. 1.2.3)}}

\def\Date#1{\gdef\@Date{#1}}
\gdef\@Date{\@latex@warning@no@line{No \noexpand\Date given %
        (e.g. 01/04/2010)}}

%\def\Activity#1{\gdef\@Activity{#1}}
%\gdef\@Activity{\@latex@warning@no@line{No \noexpand\Activity given %
%       (e.g. NA2 Dissemination and Outreach )}}

%\def\LeadPartner#1{\gdef\@LeadPartner{#1}}
%\gdef\@LeadPartner{\@latex@warning@no@line{No \noexpand\LeadPartner given %
%        (e.g. CERN, RAL )}}

%\def\DocStatus#1{\gdef\@DocStatus{#1}}
%\gdef\@DocStatus{\@latex@warning@no@line{No \noexpand\DocStatus given %
%        (e.g. DRAFT, WORKING, DELIVERED)}}

%\def\Dissemination#1{\gdef\@Dissemination{#1}}
%\gdef\@Dissemination{\@latex@warning@no@line{No \noexpand\Dissemination given %
%        (e.g. PUBLIC, INTERNAL, ...)}}


\long\def\Abstract#1{\gdef\@Abstract{#1}}
\gdef\@Abstract{\@latex@warning@no@line{No \noexpand\Abstract given}}

%%
%% Define the abstract using an environment abstract

%
% This will produce the mailto link in the PDF file
%
%
% We use the URL package, which does this nicely. The old way (\HTTP) was
% a bit buggy as it had problems with '~'s and '_'s
%
\urlstyle{sf}
\ifpdf
  \newcommand{\Email}[1]{\href{mailto:#1}{<{#1}>}}
  \newcommand{\HTTP}[1]{\href{#1}{\url{#1}}}
\else
  \newcommand{\Email}[1]{\textsf{<{#1}>}}
  \newcommand{\HTTP}[1]{\url{#1}}
\fi


%
% We now redifine \part and \section so that the table of contents
% has the sections/parts in upper case.
%
% Note: need to use \uppercase because \MakeUppercase is not robust
%
\def\@part[#1]#2{%
    \ifnum \c@secnumdepth >\m@ne
      \refstepcounter{part}%
      \addcontentsline{toc}{part}{\thepart\hspace{1em}\uppercase{#1}}%
    \else
      \addcontentsline{toc}{part}{\uppercase{#1}}%
    \fi
    {\parindent \z@ \raggedright
     \interlinepenalty \@M
     \normalfont
     \ifnum \c@secnumdepth >\m@ne
       \Large\bfseries \partname\nobreakspace\thepart
       \par\nobreak
     \fi
     \huge \bfseries #2%
     \markboth{}{}\par}%
    \nobreak
    \vskip 3ex
    \@afterheading}

\def\@sect#1#2#3#4#5#6[#7]#8{%
  \ifnum #2>\c@secnumdepth
    \let\@svsec\@empty
  \else
    \refstepcounter{#1}%
    \protected@edef\@svsec{\@seccntformat{#1}\relax}%
  \fi
  \@tempskipa #5\relax
  \ifdim \@tempskipa>\z@
    \begingroup
      #6{%
        \@hangfrom{\hskip #3\relax\@svsec}%
          \interlinepenalty \@M #8\@@par}%
    \endgroup
    \csname #1mark\endcsname{\uppercase{#7}}%
    \addcontentsline{toc}{#1}{%
      \ifnum #2>\c@secnumdepth \else
        \protect\numberline{\csname the#1\endcsname}%
      \fi
      \texorpdfstring{\uppercase{#7}}{#7}}%
  \else
    \def\@svsechd{%
      #6{\hskip #3\relax
      \@svsec #8}%
      \csname #1mark\endcsname{\uppercase{#7}}%
      \addcontentsline{toc}{#1}{%
        \ifnum #2>\c@secnumdepth \else
          \protect\numberline{\csname the#1\endcsname}%
        \fi
        \texorpdfstring{\uppercase{#7}}{#7}}}%
  \fi
  \@xsect{#5}}

% \addcontentsline{toc} expands to \contentsline{NAME}
% which in turn expands to \l@NAME.  So, to specify
% the table of contents, we must define \l@chapter, \l@section,
% \l@subsection, ... ; to specify the list of figures, we must define
% \l@figure; and so on.  Most of these can be defined with the
% \@dottedtocline command, which produces a contents line with dots
% between the title and the page number. It works as follows:
%
% \@dottedtocline{LEVEL}{INDENT}{NUMWIDTH}
%    LEVEL    : An entry is produced only if LEVEL < or = value of
%               'tocdepth' counter.  Note, \chapter is level 0, \section
%               is level 1, etc.
%    INDENT   : The indentation from the outer left margin of the start of
%               the contents line.
%    NUMWIDTH : The width of a box in which the section number is to go,
%               if TITLE includes a \numberline command.
%

\def\l@part{\@dottedtocline{1}{4em}{2.0em}}
\def\l@subsection{\@dottedtocline{2}{1.5em}{2.3em}}
\def\l@subsubsection{\@dottedtocline{3}{3.8em}{3.2em}}
\def\l@paragraph{\@dottedtocline{4}{7.0em}{4.1em}}
\def\l@subparagraph{\@dottedtocline{5}{10em}{5em}}

